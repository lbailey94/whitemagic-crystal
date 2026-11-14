#!/usr/bin/env python3
"""crystal_client.py — client-encrypted WhiteMagic Memory Crystal utility.

Provides client-side authenticated encryption (AES-256-GCM / ChaCha20-Poly1305)
for agent memory states. Plaintext is sealed locally before a caller explicitly
uses ``push``; the remote API also receives public envelope metadata, including
the tenant hash, cipher, parent ID, timestamp, size, and content address.

Spec: wm-crystal/1.0 (with optional SAIHM-aligned vNext cellId binding & DEK/KEK wrap)
Local plaintext and ciphertext limit: 2 MiB each (before JSON/base64 envelope overhead)
Content Addressing:
  - When id_kek_version is set (I1): sha256:<sha256(id_kek_version_be32 || nonce || ciphertext)>
  - Legacy 1.0 (id_kek_version None): sha256:<sha256(ciphertext)>
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import warnings
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None
    Ed25519PublicKey = None
    Encoding = None
    PublicFormat = None
    AESGCM = None
    ChaCha20Poly1305 = None

SPEC = "wm-crystal/1.0"
SALT = "whitemagic-crystal-salt-v1"
MAX_SIZE = 2 * 1024 * 1024  # local plaintext/ciphertext limit, not serialized envelope size
CRYSTAL_ID_RE = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})\Z")
SUPPORTED_CLIENT_SIG_ALGS = ("ed25519", "ed25519+ml-dsa-65")


class CrystalVerificationError(ValueError):
    """Base error for crystal set / read-path verification failures."""


class CrystalRollbackError(CrystalVerificationError):
    """Raised when a crystal store is rolled back or truncated relative to an anchor commitment."""


class CrystalUnanchoredWarning(UserWarning):
    """A crystal set was verified without an off-store anchor commitment.

    Without a signed commitment held outside the store, whole-store snapshot
    rollback (T9) and erasure resurrection (T10) cannot be detected: a restored
    copy carries any in-store commitment back with it.
    """


class CrystalLineageError(CrystalVerificationError):
    """Raised when parent_crystal_id links or sequence ordering are broken."""


class CrystalContextError(CrystalVerificationError):
    """Raised when a crystal from another tenant/context is replayed into a store."""


def compute_tenant_hash(tenant_id: str, salt: str = SALT) -> str:
    """Derive deterministic tenant hash: sha256(salt:tenant_id)."""
    digest = hashlib.sha256(f"{salt}:{tenant_id}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _ed25519_did_key_bytes(value: str) -> bytes:
    """Decode the did:key Ed25519 multicodec form used by receipt-api."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not value.startswith("did:key:z"):
        raise ValueError("expected did:key base58btc identifier")
    number = 0
    for char in value[len("did:key:z"):]:
        try:
            digit = alphabet.index(char)
        except ValueError as exc:
            raise ValueError("invalid base58btc character") from exc
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    zeros = len(value[len("did:key:z"):]) - len(value[len("did:key:z"):].lstrip("1"))
    decoded = b"\0" * zeros + decoded
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ValueError("did:key is not an Ed25519 public key")
    return decoded[2:]


def _canonical_receipt_bytes(value: Any) -> bytes:
    """Encode the continuity-receipt v0 canonical JSON subset used by service."""
    def validate(item: Any) -> None:
        if isinstance(item, float):
            raise ValueError("floats are not allowed in continuity receipts")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("receipt object keys must be strings")
            for child in item.values():
                validate(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                validate(child)
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_crystal_id(
    ciphertext: bytes,
    nonce: bytes | None = None,
    id_kek_version: int | None = None,
) -> str:
    """Compute canonical crystal_id (I1).

    When ``id_kek_version`` (>= 1) is supplied, binds key version and nonce into
    the content address: ``sha256(id_kek_version_be32 || nonce || ciphertext)``.
    When ``id_kek_version`` is None, preserves legacy 1.0 ``sha256(ciphertext)``.
    """
    if id_kek_version is not None:
        if isinstance(id_kek_version, bool) or not isinstance(id_kek_version, int) or id_kek_version < 1 or id_kek_version > 0xFFFFFFFF:
            raise ValueError(f"id_kek_version must be an integer in 1..2^32-1, got {id_kek_version!r}")
        if nonce is None:
            raise ValueError("nonce is required when id_kek_version is bound into crystal_id")
        preimage = int(id_kek_version).to_bytes(4, "big") + nonce + ciphertext
        return f"sha256:{hashlib.sha256(preimage).hexdigest()}"
    return f"sha256:{hashlib.sha256(ciphertext).hexdigest()}"


def build_aad(
    cipher: str,
    tenant_hash: str,
    parent_crystal_id: str | None,
    created_at: str,
    metadata_public: dict[str, Any] | None = None,
    bind_metadata: bool = False,
) -> bytes:
    """Bind cipher, tenant hash, parent ID, creation time (and metadata when kek_version is set) as AEAD data."""
    parent_str = parent_crystal_id if parent_crystal_id is not None else "genesis"
    base = f"{cipher}|{tenant_hash}|{parent_str}|{created_at}"
    if bind_metadata:
        meta_canon = json.dumps(metadata_public or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        base = f"{base}|{meta_canon}"
    return base.encode("utf-8")


def generate_key(cipher: str = "AES-256-GCM") -> bytes:
    """Generate a random 32-byte cryptographic key."""
    _normalize_cipher(cipher)
    return os.urandom(32)


def _normalize_cipher(cipher: str) -> str:
    normalized = cipher.lower().replace("_", "-")
    if normalized in ("aes-256-gcm", "chacha20-poly1305"):
        return normalized
    raise ValueError(f"unsupported cipher: {cipher}")


def _require_crypto() -> None:
    if AESGCM is None or ChaCha20Poly1305 is None:
        raise RuntimeError(
            "cryptography library required for crystal operations (pip install cryptography)"
        )


def _aead_for(cipher_norm: str, key: bytes):
    if cipher_norm == "aes-256-gcm":
        return AESGCM(key)
    if cipher_norm == "chacha20-poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"unsupported cipher: {cipher_norm}")


def wrap_crystal_dek(
    dek: bytes,
    kek: bytes,
    crystal_id: str,
    kek_version: int,
    cipher: str = "aes-256-gcm",
) -> str:
    """Wrap a 32-byte per-crystal DEK under a client KEK v(N) (I2)."""
    _require_crypto()
    if len(dek) != 32 or len(kek) != 32:
        raise ValueError("DEK and KEK must both be 32 bytes")
    if isinstance(kek_version, bool) or not isinstance(kek_version, int) or kek_version < 1:
        raise ValueError("kek_version must be a positive integer")
    cipher_norm = _normalize_cipher(cipher)
    wrap_nonce = os.urandom(12)
    wrap_aad = f"wm-crystal-dek-wrap-v1|{crystal_id.lower()}|{kek_version}".encode("utf-8")
    wrapped_ct = _aead_for(cipher_norm, kek).encrypt(wrap_nonce, dek, wrap_aad)
    return base64.urlsafe_b64encode(wrap_nonce + wrapped_ct).decode("ascii")


def unwrap_crystal_dek(
    wrapped_dek: str,
    kek: bytes,
    crystal_id: str,
    kek_version: int,
    cipher: str = "aes-256-gcm",
) -> bytes:
    """Unwrap a 32-byte per-crystal DEK using client KEK v(N) (I2)."""
    _require_crypto()
    if len(kek) != 32:
        raise ValueError("KEK must be 32 bytes")
    if isinstance(kek_version, bool) or not isinstance(kek_version, int) or kek_version < 1:
        raise ValueError("kek_version must be a positive integer")
    raw = base64.urlsafe_b64decode(wrapped_dek)
    if len(raw) != 60:
        raise ValueError(f"invalid wrapped_dek length: {len(raw)} bytes (expected 60)")
    wrap_nonce, wrapped_ct = raw[:12], raw[12:]
    cipher_norm = _normalize_cipher(cipher)
    wrap_aad = f"wm-crystal-dek-wrap-v1|{crystal_id.lower()}|{kek_version}".encode("utf-8")
    return _aead_for(cipher_norm, kek).decrypt(wrap_nonce, wrapped_ct, wrap_aad)


def _require_https_api(api_url: str) -> str:
    parsed = urllib.parse.urlsplit(api_url)
    if (parsed.scheme != "https" or not parsed.netloc or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("API URL must be an HTTPS origin without embedded credentials")
    if parsed.path not in ("", "/"):
        raise ValueError("API URL must be an HTTPS origin without a path")
    if parsed.query or parsed.fragment:
        raise ValueError("API URL must not include a query or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("API URL has an invalid port") from exc
    return api_url.rstrip("/")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so push credentials cannot be forwarded elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "redirect refused for crystal API request",
            headers,
            fp,
        )


def _authenticated_request(url: str, *, method: str, auth_token: str,
                           data: bytes | None = None, content_type: bool = False) -> Any:
    parts = urllib.parse.urlsplit(url)
    origin = _require_https_api(urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", "")))
    if not isinstance(auth_token, str) or not auth_token.strip():
        raise ValueError("auth_token is required")
    path = urllib.parse.urlsplit(url).path
    target = origin + path
    headers = {"User-Agent": "whitemagic-crystal-client/1.0", "Authorization": f"Bearer {auth_token}"}
    if auth_token.startswith("wm_pass_"):
        headers["X-Session-Pass"] = auth_token
    if content_type:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data or b""))
    req = urllib.request.Request(target, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirectHandler)
    return opener.open(req, timeout=30)


def seal_crystal(
    content: str | bytes | dict,
    key: bytes,
    tenant_id: str,
    parent_crystal_id: str | None = None,
    metadata_public: dict[str, Any] | None = None,
    cipher: str = "aes-256-gcm",
    owner_locator: str | None = None,
    kek_version: int | None = None,
) -> dict[str, Any]:
    """Seal memory content locally into a client-encrypted crystal envelope.

    When ``kek_version`` (>= 1) is supplied (I1/I2):
      1. Generates a random 32-byte per-crystal DEK to encrypt the payload.
      2. Binds ``kek_version_be32 || nonce || ciphertext`` into ``crystal_id``.
      3. Wraps the DEK under ``key`` (acting as client KEK v(N)) and stores
         ``kek_version``, ``id_kek_version``, and ``wrapped_dek`` in the envelope.
    """
    _require_crypto()
    if len(key) != 32:
        raise ValueError("encryption key must be exactly 32 bytes (256-bit)")
    if kek_version is not None and (isinstance(kek_version, bool) or not isinstance(kek_version, int) or kek_version < 1):
        raise ValueError("kek_version must be a positive integer")

    cipher_norm = _normalize_cipher(cipher)

    if isinstance(content, dict):
        raw_plaintext = json.dumps(content, sort_keys=True).encode("utf-8")
    elif isinstance(content, str):
        raw_plaintext = content.encode("utf-8")
    else:
        raw_plaintext = content

    if len(raw_plaintext) > MAX_SIZE:
        raise ValueError(f"plaintext size {len(raw_plaintext)} exceeds maximum {MAX_SIZE} bytes")

    if owner_locator is None:
        tenant_hash = compute_tenant_hash(tenant_id)
    elif not isinstance(owner_locator, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", owner_locator):
        raise ValueError("owner_locator must be sha256:<64 lowercase hex> from authenticated bootstrap")
    else:
        tenant_hash = owner_locator
    created_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta_dict = metadata_public or {}
    aad = build_aad(
        cipher_norm,
        tenant_hash,
        parent_crystal_id,
        created_at,
        metadata_public=meta_dict,
        bind_metadata=(kek_version is not None),
    )

    nonce = os.urandom(12)
    payload_key = os.urandom(32) if kek_version is not None else key
    ciphertext = _aead_for(cipher_norm, payload_key).encrypt(nonce, raw_plaintext, aad)

    if len(ciphertext) > MAX_SIZE:
        raise ValueError(f"ciphertext size {len(ciphertext)} exceeds maximum {MAX_SIZE} bytes")

    crystal_id = compute_crystal_id(ciphertext, nonce=nonce, id_kek_version=kek_version)

    envelope: dict[str, Any] = {
        "spec": SPEC,
        "crystal_id": crystal_id,
        "parent_crystal_id": parent_crystal_id,
        "tenant_hash": tenant_hash,
        "cipher": cipher_norm,
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "size_bytes": len(ciphertext),
        "created_at": created_at,
        "metadata_public": meta_dict,
    }
    if kek_version is not None:
        envelope["kek_version"] = kek_version
        envelope["id_kek_version"] = kek_version
        envelope["wrapped_dek"] = wrap_crystal_dek(
            payload_key, key, crystal_id, kek_version, cipher=cipher_norm
        )
    return envelope


def _canonical_envelope_bytes_for_sig(envelope: dict[str, Any]) -> bytes:
    body = {k: v for k, v in envelope.items() if k != "client_sig" and not k.startswith("_")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_crystal_envelope(
    crystal_envelope: dict[str, Any],
    ed25519_private_key: bytes,
    *,
    pq_alg: str | None = None,
    pq_public_key_b64: str | None = None,
    pq_sig_b64: str | None = None,
) -> dict[str, Any]:
    """Attach an Ed25519 or hybrid Ed25519+ML-DSA-65 client_sig over the canonical envelope (I4)."""
    _require_crypto()
    if len(ed25519_private_key) != 32:
        raise ValueError("ed25519_private_key must be 32 bytes")
    priv = Ed25519PrivateKey.from_private_bytes(ed25519_private_key)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signed = dict(crystal_envelope)
    canon = _canonical_envelope_bytes_for_sig(signed)
    ed_sig = priv.sign(canon)
    sig_obj: dict[str, Any] = {
        "alg": "ed25519+ml-dsa-65" if pq_sig_b64 else "ed25519",
        "public_key": pub_bytes.hex(),
        "sig": base64.urlsafe_b64encode(ed_sig).decode("ascii"),
    }
    if pq_sig_b64:
        if pq_alg and pq_alg not in ("ml-dsa-65", "ed25519+ml-dsa-65"):
            raise ValueError(f"unsupported PQ signature algorithm: {pq_alg}")
        if not pq_public_key_b64 or not isinstance(pq_public_key_b64, str):
            raise ValueError("pq_public_key_b64 is required when pq_sig_b64 is supplied")
        sig_obj["pq_alg"] = "ml-dsa-65"
        sig_obj["pq_public_key"] = pq_public_key_b64
        sig_obj["pq_sig"] = pq_sig_b64
    signed["client_sig"] = sig_obj
    return signed


def verify_crystal_client_sig(
    crystal_envelope: dict[str, Any],
    *,
    pq_verifier=None,
) -> bool:
    """Verify optional client_sig (Ed25519 or hybrid Ed25519+ML-DSA-65) on a crystal envelope (I4).

    Fail-closed policy:
      - Standalone 'ml-dsa-65' without Ed25519 is rejected.
      - Every supported profile MUST carry and verify a valid Ed25519 signature over canonical envelope bytes.
      - Hybrid 'ed25519+ml-dsa-65' requires both non-empty pq_public_key/pq_sig AND an explicit
        pq_verifier callback that returns True; omitting pq_verifier fails closed.
    """
    sig_obj = crystal_envelope.get("client_sig")
    if sig_obj is None:
        return True
    _require_crypto()
    if not isinstance(sig_obj, dict):
        raise CrystalVerificationError("client_sig must be an object")
    alg = str(sig_obj.get("alg") or "")
    if alg not in SUPPORTED_CLIENT_SIG_ALGS:
        raise CrystalVerificationError(f"unsupported client_sig alg: {alg!r}")
    canon = _canonical_envelope_bytes_for_sig(crystal_envelope)
    pub_hex = str(sig_obj.get("public_key") or "")
    sig_b64 = str(sig_obj.get("sig") or "")
    try:
        pub_raw = bytes.fromhex(pub_hex)
        if len(pub_raw) != 32:
            raise CrystalVerificationError("Ed25519 public_key must be 32 bytes")
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        pub.verify(raw_sig, canon)
    except Exception as exc:
        raise CrystalVerificationError(f"client_sig Ed25519 verification failed: {exc}") from exc

    if alg == "ed25519+ml-dsa-65":
        pq_alg = sig_obj.get("pq_alg")
        if pq_alg not in (None, "ml-dsa-65"):
            raise CrystalVerificationError(f"unsupported hybrid pq_alg: {pq_alg!r}")
        pq_sig = sig_obj.get("pq_sig")
        pq_pub = sig_obj.get("pq_public_key")
        if not pq_sig or not isinstance(pq_sig, str):
            raise CrystalVerificationError("client_sig missing pq_sig for hybrid ML-DSA-65 profile")
        if not pq_pub or not isinstance(pq_pub, str):
            raise CrystalVerificationError("client_sig missing pq_public_key for hybrid ML-DSA-65 profile")
        if pq_verifier is None:
            raise CrystalVerificationError(
                "client_sig uses hybrid ed25519+ml-dsa-65 profile, which requires an explicit pq_verifier callback (fail-closed)"
            )
        if not pq_verifier(pq_pub, canon, pq_sig):
            raise CrystalVerificationError("client_sig ML-DSA-65 verification failed")
    return True


def unseal_crystal(
    crystal_envelope: dict[str, Any],
    key: bytes,
    *,
    pq_verifier=None,
) -> bytes:
    """Client-side unseal and verification of a Memory Crystal envelope."""
    _require_crypto()
    if len(key) != 32:
        raise ValueError("encryption key must be exactly 32 bytes (256-bit)")

    if crystal_envelope.get("dek_destroyed") is True or (
        "kek_version" in crystal_envelope and crystal_envelope.get("wrapped_dek") is None
    ):
        raise CrystalVerificationError("crystal DEK has been scrubbed from this envelope; cannot decrypt without wrapped_dek")

    for field in ("crystal_id", "tenant_hash", "cipher", "nonce", "ciphertext", "created_at"):
        if field not in crystal_envelope:
            raise CrystalVerificationError(f"malformed envelope: missing field {field!r}")

    if "client_sig" in crystal_envelope:
        verify_crystal_client_sig(crystal_envelope, pq_verifier=pq_verifier)

    cipher_norm = _normalize_cipher(crystal_envelope["cipher"])
    nonce = base64.urlsafe_b64decode(crystal_envelope["nonce"])
    ciphertext = base64.urlsafe_b64decode(crystal_envelope["ciphertext"])

    kek_version = crystal_envelope.get("kek_version")
    id_kek_version = crystal_envelope.get("id_kek_version", kek_version)
    expected_id = compute_crystal_id(ciphertext, nonce=nonce, id_kek_version=id_kek_version)
    if crystal_envelope["crystal_id"].lower() != expected_id.lower():
        raise CrystalVerificationError(f"crystal content-address verification failed: {crystal_envelope['crystal_id']} != {expected_id}")

    payload_key = key
    if crystal_envelope.get("wrapped_dek") is not None:
        if kek_version is None:
            raise CrystalVerificationError("malformed envelope: wrapped_dek present without kek_version")
        payload_key = unwrap_crystal_dek(
            crystal_envelope["wrapped_dek"],
            key,
            crystal_envelope["crystal_id"],
            int(kek_version),
            cipher=cipher_norm,
        )

    aad = build_aad(
        cipher_norm,
        crystal_envelope["tenant_hash"],
        crystal_envelope.get("parent_crystal_id"),
        crystal_envelope["created_at"],
        metadata_public=crystal_envelope.get("metadata_public") if isinstance(crystal_envelope.get("metadata_public"), dict) else {},
        bind_metadata=(id_kek_version is not None),
    )
    try:
        return _aead_for(cipher_norm, payload_key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise CrystalVerificationError(f"AEAD decryption or integrity tag verification failed: {exc}") from exc


def _erased_ids_digest(erasures: list[dict[str, Any]]) -> tuple[int, str]:
    """(count, digest) over the sorted set of erased crystal ids."""
    erased_ids = sorted({str(e.get("crystal_id", "")).lower() for e in erasures})
    digest = "sha256:" + hashlib.sha256("\n".join(erased_ids).encode("utf-8")).hexdigest()
    return len(erased_ids), digest


def _check_erasure_binding(
    commitment: dict[str, Any],
    erasures: list[dict[str, Any]] | None,
    crystal_ids: list[str],
    where: str,
) -> None:
    """T10 (erasure resurrection): an erasure-aware commitment must still match
    the store after a pre-erasure copy has been restored over it.

    A high-water cell count alone cannot catch this: erasure *lowers* the count,
    so a restored pre-erasure copy is a superset of what the anchor recorded and
    passes a ``len(store) >= count`` check. The commitment therefore also carries
    ``erasure_count``, ``erased_crystal_ids_digest`` and ``revision`` (cells +
    erasures, which strictly increases on every add *and* every erase).
    """
    if "revision" not in commitment and "erasure_count" not in commitment:
        return
    if erasures is None:
        raise CrystalRollbackError(
            f"{where}: anchor commits to an erasure-aware state but no erasure list was supplied"
        )
    count, digest = _erased_ids_digest(erasures)
    if count != int(commitment.get("erasure_count", -1)):
        raise CrystalRollbackError(
            f"{where}: erasure_count mismatch: store has {count}, anchor committed to {commitment.get('erasure_count')}"
        )
    if digest != commitment.get("erased_crystal_ids_digest"):
        raise CrystalRollbackError(f"{where}: erased_crystal_ids_digest mismatch against anchor commitment")
    revision = len(crystal_ids) + count
    if "revision" in commitment and revision != int(commitment["revision"]):
        raise CrystalRollbackError(
            f"{where}: revision mismatch: store is at {revision}, anchor committed to {commitment['revision']}"
        )
    erased = {str(e.get("crystal_id", "")).lower() for e in erasures}
    overlap = sorted(erased.intersection(crystal_ids))
    if overlap:
        raise CrystalRollbackError(f"{where}: erased crystal served again: {overlap[0]}")


def compute_crystal_set_commitment(
    crystals: list[dict[str, Any]],
    tenant_hash: str,
    *,
    retrieved_at: str | None = None,
    signing_key: bytes | None = None,
    erasures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute an export-level head and ordered-set commitment over a sequence of crystals (I6).

    Binds ``count``, ``ordered_crystal_ids_digest``, ``head_crystal_id``, ``tenant_hash``,
    ``spec``, and ``retrieved_at`` inside the signed commitment payload. When
    ``erasures`` is supplied it also binds ``erasure_count``,
    ``erased_crystal_ids_digest`` and ``revision``, which is what lets a verifier
    catch a restored pre-erasure copy (T10).
    """
    ordered_ids = [str(c["crystal_id"]).lower() for c in crystals]
    ordered_digest = "sha256:" + hashlib.sha256("\n".join(ordered_ids).encode("utf-8")).hexdigest()
    head_id = ordered_ids[-1] if ordered_ids else None
    ts = retrieved_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commitment: dict[str, Any] = {
        "kind": "wm.crystal-set-commitment",
        "version": 1,
        "spec": SPEC,
        "tenant_hash": tenant_hash,
        "count": len(ordered_ids),
        "ordered_crystal_ids_digest": ordered_digest,
        "head_crystal_id": head_id,
        "retrieved_at": ts,
    }
    if erasures is not None:
        erasure_count, erasure_digest = _erased_ids_digest(erasures)
        commitment["erasure_count"] = erasure_count
        commitment["erased_crystal_ids_digest"] = erasure_digest
        commitment["revision"] = len(ordered_ids) + erasure_count
    canon = json.dumps(commitment, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    commitment_digest = "sha256:" + hashlib.sha256(canon).hexdigest()
    if signing_key is not None:
        _require_crypto()
        if len(signing_key) != 32:
            raise ValueError("signing_key must be 32-byte Ed25519 seed")
        priv = Ed25519PrivateKey.from_private_bytes(signing_key)
        pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        sig_b64 = base64.urlsafe_b64encode(priv.sign(canon)).decode("ascii")
        commitment["sig"] = {
            "alg": "ed25519",
            "public_key": pub_hex,
            "value": sig_b64,
        }
    commitment["commitment_digest"] = commitment_digest
    return commitment


def _require_32b_key(raw: bytes, label: str) -> bytes:
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes")
    return raw


def _validate_commitment_envelope(
    expected_commitment: dict[str, Any],
    expected_tenant_hash: str,
    *,
    anchor_public_key: bytes | None = None,
) -> None:
    """Validate structure, digest, signature, and tenant binding on a set commitment."""
    if not isinstance(expected_commitment, dict) or expected_commitment.get("kind") != "wm.crystal-set-commitment":
        raise CrystalRollbackError("invalid or missing crystal-set commitment")
    version = expected_commitment.get("version")
    if type(version) is not int or version != 1:
        raise CrystalRollbackError("unsupported or invalid anchor commitment version")
    if expected_commitment.get("spec") != SPEC:
        raise CrystalRollbackError("anchor commitment spec mismatch")
    count = expected_commitment.get("count")
    if type(count) is not int or count < 0:
        raise CrystalRollbackError("invalid anchor commitment count")
    if expected_commitment.get("tenant_hash") != expected_tenant_hash:
        raise CrystalContextError("anchor commitment tenant_hash mismatch")
    for int_field in ("erasure_count", "revision"):
        if int_field in expected_commitment:
            val = expected_commitment[int_field]
            if type(val) is not int or val < 0:
                raise CrystalRollbackError(f"invalid anchor commitment {int_field}")
    unsigned = {
        k: v for k, v in expected_commitment.items()
        if k not in ("sig", "commitment_digest")
    }
    canon = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    expected_digest = "sha256:" + hashlib.sha256(canon).hexdigest()
    carried_digest = expected_commitment.get("commitment_digest")
    if carried_digest is not None and carried_digest != expected_digest:
        raise CrystalRollbackError("anchor commitment_digest mismatch")
    if anchor_public_key is not None:
        _require_crypto()
        pub_key_bytes = _require_32b_key(anchor_public_key, "anchor_public_key")
        sig_obj = expected_commitment.get("sig")
        if not isinstance(sig_obj, dict) or sig_obj.get("alg") != "ed25519":
            raise CrystalRollbackError("anchor commitment is unsigned or uses unsupported alg")
        carried_pub = sig_obj.get("public_key")
        if not isinstance(carried_pub, str) or carried_pub.lower() != pub_key_bytes.hex().lower():
            raise CrystalRollbackError("anchor commitment public_key mismatch")
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            sig_str = str(sig_obj.get("value") or "")
            raw_sig = base64.urlsafe_b64decode(sig_str + "=" * (-len(sig_str) % 4))
            pub.verify(raw_sig, canon)
        except Exception as exc:
            raise CrystalRollbackError(f"anchor commitment signature invalid: {exc}") from exc


def resolve_offstore_anchor_path(
    store_path: str | os.PathLike[str],
    *,
    tenant_hash: str | None = None,
    base_dir: str | os.PathLike[str] | None = None,
) -> Path:
    """Resolve an anchor path outside the resolved store directory tree.

    An existing store file uses its resolved parent as the store boundary;
    other store paths are treated as directories. When ``base_dir`` is omitted,
    use ``<store_dir>.anchor`` or ``~/.whitemagic/anchors/<tenant_hash>/``.
    Tenant hashes must use the canonical ``sha256:<64 lowercase hex>`` form
    returned by :func:`compute_tenant_hash`.

    This performs no writes or directory creation. It checks the current
    resolved paths, including existing symlinks; it does not ensure independent
    retention, a separate filesystem, or safety against later path replacement.
    """
    if tenant_hash is not None and (
        not isinstance(tenant_hash, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", tenant_hash) is None
    ):
        raise ValueError("tenant_hash must be sha256:<64 lowercase hex digits>")
    p = Path(store_path).resolve()
    store_dir = p.parent if p.is_file() else p
    if base_dir is not None:
        anchor_root = Path(base_dir)
    elif tenant_hash is not None:
        anchor_root = Path.home() / ".whitemagic" / "anchors" / tenant_hash
    else:
        anchor_root = store_dir.parent / f"{store_dir.name}.anchor"
    candidate = (anchor_root / "commitment.json").resolve()
    if candidate.is_relative_to(store_dir):
        raise ValueError("anchor commitment path must be outside the resolved store directory")
    return candidate


def _ensure_private_dir(target: Path, *, managed_ancestor: Path | None = None) -> None:
    """Create directories up to ``target`` with 0700 permissions and no managed symlinks."""
    resolved_ancestor = managed_ancestor.absolute() if managed_ancestor is not None else target.parent.absolute()
    chain: list[Path] = []
    cur = target.absolute()
    while True:
        chain.append(cur)
        if cur == cur.parent or (cur.exists() and (cur == resolved_ancestor or resolved_ancestor not in cur.parents)):
            break
        cur = cur.parent
    for directory in reversed(chain):
        if os.path.islink(directory):
            if directory == chain[-1] and directory != target.absolute():
                continue
            raise CrystalVerificationError(f"refusing symlinked storage directory: {directory}")
        if directory.exists():
            st = os.lstat(directory)
            if not stat.S_ISDIR(st.st_mode):
                raise CrystalVerificationError(f"storage path is not a directory: {directory}")
            if directory == target.absolute() and os.name == "posix" and st.st_uid == os.getuid() and (st.st_mode & 0o077):
                os.chmod(directory, 0o700)
        else:
            os.mkdir(directory, 0o700)
            if os.name == "posix":
                os.chmod(directory, 0o700)


def _read_json_nofollow(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> Any | None:
    """Read JSON from a non-symlink regular file; return None if absent."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CrystalVerificationError(f"refusing unsafe storage file {path}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CrystalVerificationError(f"storage path must be a regular file: {path}")
        if st.st_size > max_bytes:
            raise CrystalVerificationError(f"storage file exceeds {max_bytes} bytes: {path}")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            raw = stream.read(max_bytes + 1)
            if len(raw.encode("utf-8")) > max_bytes:
                raise CrystalVerificationError(f"storage file exceeds {max_bytes} bytes: {path}")
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise CrystalVerificationError(f"corrupted JSON in storage file {path}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _write_json_atomic(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    """Atomically write JSON without following a symlink at ``path``."""
    if os.path.islink(path):
        raise CrystalVerificationError(f"refusing to write through symlink: {path}")
    encoded = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(6).hex()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp_path, flags, mode)
    try:
        view = memoryview(encoded)
        written = 0
        while written < len(encoded):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise OSError("short write while persisting crystal state")
            written += n
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    os.close(fd)
    if os.path.islink(path):
        os.unlink(tmp_path)
        raise CrystalVerificationError(f"refusing to replace symlink: {path}")
    os.replace(tmp_path, path)
    if os.name == "posix":
        os.chmod(path, mode)


def _default_anchor_base_dir(store_dir: Path, tenant_hash: str) -> tuple[Path, Path]:
    """Return ``(managed_root, scoped_anchor_dir)`` outside ``store_dir``."""
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    if xdg and Path(xdg).is_absolute():
        managed_root = Path(xdg)
        anchor_root = managed_root / "whitemagic" / "anchors"
    else:
        managed_root = Path.home()
        anchor_root = managed_root / ".whitemagic" / "anchors"
    store_scope = hashlib.sha256(str(store_dir).encode("utf-8")).hexdigest()[:16]
    return managed_root, anchor_root / tenant_hash / store_scope


def _load_or_create_offstore_anchor_seed(key_path: Path) -> bytes:
    """Load or atomically provision a 32-byte Ed25519 anchor seed outside ``store_dir``."""
    if os.path.islink(key_path):
        raise CrystalVerificationError(f"refusing symlinked anchor key file: {key_path}")
    flags_r = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(key_path, flags_r)
    except FileNotFoundError:
        seed = generate_key()
        flags_w = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            wfd = os.open(key_path, flags_w, 0o600)
        except FileExistsError:
            return _load_or_create_offstore_anchor_seed(key_path)
        try:
            os.write(wfd, seed)
            os.fsync(wfd)
        finally:
            os.close(wfd)
        return seed
    except OSError as exc:
        raise CrystalVerificationError(f"refusing unsafe anchor key file {key_path}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CrystalVerificationError(f"anchor key must be a regular file: {key_path}")
        if os.name == "posix" and st.st_mode & 0o077:
            raise CrystalVerificationError(f"anchor key permissions must be 0600 or stricter: {key_path}")
        raw = os.read(fd, 65)
    finally:
        os.close(fd)
    if len(raw) == 32:
        return raw
    if len(raw.strip()) == 64:
        return bytes.fromhex(raw.strip().decode("ascii"))
    raise CrystalVerificationError(f"invalid anchor key length in {key_path}")


def verify_and_unseal_crystal_set(
    crystals: list[dict[str, Any]],
    key: bytes,
    expected_tenant_hash: str,
    *,
    expected_commitment: dict[str, Any] | None = None,
    anchor_public_key: bytes | None = None,
    erasures: list[dict[str, Any]] | None = None,
    require_anchor: bool = True,
) -> list[bytes]:
    """Read-path verifier for an ordered crystal set before session resumption (I6/I7).

    Checks:
      1. Anchored export commitment (signature, tenant_hash, high-water count,
         anchored head_crystal_id, and ordered_crystal_ids_digest) -> rejects T9 whole-store
         rollback and T2 tail truncation. Required by default (Phase 2 strict policy);
         pass require_anchor=False to explicitly opt out. The flag must be a
         boolean; other values are rejected even when a commitment is supplied.
      2. Context binding (tenant_hash == expected_tenant_hash) -> rejects T6 cross-context replay.
      3. Lineage DAG continuity (genesis parent is None; each subsequent crystal's
         parent_crystal_id equals the immediately preceding crystal_id) -> rejects
         T2/T3 deletion, T4 reordering, and T7 single-record rollback.
      4. Per-crystal content address (I1), optional client_sig (I4), DEK unwrap (I2),
         and AEAD decryption over AAD (cipher, tenant_hash, parent, created_at, metadata)
         -> rejects T1 payload edits, T5 forged records, and T8 metadata edits.
    """
    if not isinstance(require_anchor, bool):
        raise CrystalVerificationError("require_anchor must be a boolean")
    if expected_commitment is None:
        # Phase 2 strict anchor policy: default is True (fail-closed against rollback).
        if require_anchor:
            raise CrystalRollbackError(
                "no off-store anchor commitment supplied; whole-store rollback (T9) and erasure "
                "resurrection (T10) cannot be detected without an independently retained commitment. "
                "Provide expected_commitment=... or pass require_anchor=False to explicitly opt out."
            )
    if expected_commitment is not None:
        _validate_commitment_envelope(
            expected_commitment,
            expected_tenant_hash,
            anchor_public_key=anchor_public_key,
        )
        _check_erasure_binding(
            expected_commitment,
            erasures,
            [str(c.get("crystal_id", "")).lower() for c in crystals if isinstance(c, dict)],
            "crystal set",
        )

    plaintexts: list[bytes] = []
    seen_ids: set[str] = set()
    for idx, env in enumerate(crystals):
        if not isinstance(env, dict):
            raise CrystalVerificationError(f"crystal at index {idx} is not an object")
        if env.get("tenant_hash") != expected_tenant_hash:
            raise CrystalContextError(
                f"cross-context crystal replay at index {idx}: tenant_hash {env.get('tenant_hash')} != {expected_tenant_hash}"
            )
        pt = unseal_crystal(env, key)
        cid = str(env["crystal_id"]).lower()
        if cid in seen_ids:
            raise CrystalLineageError(f"duplicate crystal_id at index {idx}: {cid}")
        seen_ids.add(cid)
        parent = env.get("parent_crystal_id")
        if idx == 0:
            if parent is not None:
                raise CrystalLineageError(f"genesis crystal at index 0 has non-null parent_crystal_id: {parent}")
        else:
            prev_id = str(crystals[idx - 1]["crystal_id"]).lower()
            if str(parent or "").lower() != prev_id:
                raise CrystalLineageError(
                    f"lineage link broken at index {idx}: parent_crystal_id {parent} != previous {prev_id}"
                )
        plaintexts.append(pt)

    if expected_commitment is not None:
        exp_count = int(expected_commitment.get("count", 0))
        if len(crystals) < exp_count:
            raise CrystalRollbackError(
                f"store rollback or truncation detected: store has {len(crystals)} crystals, anchor committed to {exp_count}"
            )
        prefix_ids = [str(c["crystal_id"]).lower() for c in crystals[:exp_count]]
        actual_digest = "sha256:" + hashlib.sha256("\n".join(prefix_ids).encode("utf-8")).hexdigest()
        exp_head = expected_commitment.get("head_crystal_id")
        actual_head = prefix_ids[-1] if prefix_ids else None
        if (exp_head or None) != actual_head:
            raise CrystalRollbackError(
                f"anchored head mismatch: expected {exp_head}, found {actual_head}"
            )
        if expected_commitment.get("ordered_crystal_ids_digest") != actual_digest:
            raise CrystalRollbackError(
                "ordered_crystal_ids_digest mismatch against anchor commitment"
            )

    return plaintexts


class LocalCrystalStore:
    """Stateful local Memory Crystal store with automatic off-store anchor persistence.

    Stores sealed ``wm-crystal/1.0`` envelopes (``crystals.json``) and erasure
    tombstones (``erasures.json``) inside ``store_dir``, while automatically
    maintaining a signed erasure-aware ``wm.crystal-set-commitment`` outside
    ``store_dir`` (defaulting to ``$XDG_STATE_HOME/whitemagic/anchors`` or
    ``~/.whitemagic/anchors`` scoped by tenant and store directory).

    Threat boundary note: keeping the anchor outside ``store_dir`` in user state
    or an explicit ``anchor_base_dir`` defeats store-directory tampering,
    whole-store snapshot rollback (T9), and erasure resurrection (T10) by an
    attacker limited to ``store_dir``. Against an attacker with full-host write
    access, supply an anchor path on a separate volume or pair commits with a
    remote notary receipt.
    """

    STORE_FILE = "crystals.json"
    ERASURES_FILE = "erasures.json"

    def __init__(
        self,
        store_dir: str | os.PathLike[str],
        *,
        key: bytes,
        tenant_id: str,
        anchor_signing_key: bytes | None = None,
        anchor_public_key: bytes | None = None,
        anchor_base_dir: str | os.PathLike[str] | None = None,
        anchor_path: str | os.PathLike[str] | None = None,
        cipher: str = "aes-256-gcm",
        kek_version: int | None = 1,
        require_anchor: bool = True,
        create: bool = True,
    ) -> None:
        _require_crypto()
        self.key = _require_32b_key(key, "encryption key")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("tenant_id must be a non-empty string")
        if not isinstance(require_anchor, bool):
            raise CrystalVerificationError("require_anchor must be a boolean")
        if not isinstance(create, bool):
            raise ValueError("create must be a boolean")
        if kek_version is not None and (isinstance(kek_version, bool) or not isinstance(kek_version, int) or kek_version < 1):
            raise ValueError("kek_version must be a positive integer or None")

        self.tenant_id = tenant_id
        self.tenant_hash = compute_tenant_hash(tenant_id)
        self.cipher = _normalize_cipher(cipher)
        self.kek_version = kek_version
        self.require_anchor = require_anchor

        raw_store = Path(store_dir)
        if os.path.islink(raw_store):
            raise CrystalVerificationError(f"refusing symlinked store directory: {raw_store}")
        if raw_store.exists():
            if not raw_store.is_dir():
                raise CrystalVerificationError(f"store_dir is not a directory: {raw_store}")
        elif not create:
            raise CrystalVerificationError(f"store directory does not exist: {raw_store}")
        else:
            _ensure_private_dir(raw_store, managed_ancestor=raw_store.parent)
        self.store_dir = raw_store.resolve()
        self.crystals_path = self.store_dir / self.STORE_FILE
        self.erasures_path = self.store_dir / self.ERASURES_FILE

        if anchor_path is not None and anchor_base_dir is not None:
            raise ValueError("specify at most one of anchor_path or anchor_base_dir")

        if anchor_path is not None:
            raw_anchor = Path(anchor_path)
            if os.path.islink(raw_anchor) or os.path.islink(raw_anchor.parent):
                raise CrystalVerificationError(f"refusing symlinked off-store anchor path: {raw_anchor}")
            resolved_anchor = raw_anchor.resolve()
            if resolved_anchor.is_relative_to(self.store_dir):
                raise ValueError("anchor commitment path must be outside the resolved store directory")
            self.anchor_path = resolved_anchor
            self.anchor_dir = self.anchor_path.parent
            managed_anchor_ancestor = self.anchor_dir.parent
        else:
            if anchor_base_dir is not None:
                store_scope = hashlib.sha256(str(self.store_dir).encode("utf-8")).hexdigest()[:16]
                raw_root = Path(anchor_base_dir)
                if os.path.islink(raw_root):
                    raise CrystalVerificationError(f"refusing symlinked anchor_base_dir: {raw_root}")
                scoped_base = raw_root / self.tenant_hash / store_scope
                managed_anchor_ancestor = raw_root.resolve()
            else:
                managed_root, scoped_base = _default_anchor_base_dir(self.store_dir, self.tenant_hash)
                managed_anchor_ancestor = managed_root.resolve() if managed_root.exists() else managed_root
            for candidate_parent in (scoped_base, scoped_base.parent, scoped_base / "commitment.json"):
                if os.path.islink(candidate_parent):
                    raise CrystalVerificationError(f"refusing symlinked off-store anchor location: {candidate_parent}")
            # Validate boundary before creating directories.
            resolved_candidate = resolve_offstore_anchor_path(
                self.store_dir,
                tenant_hash=self.tenant_hash,
                base_dir=scoped_base,
            )
            self.anchor_path = resolved_candidate
            self.anchor_dir = resolved_candidate.parent

        _ensure_private_dir(self.anchor_dir, managed_ancestor=managed_anchor_ancestor)
        # Re-validate after directory creation in case an intermediate path resolved inward.
        if self.anchor_path.resolve().is_relative_to(self.store_dir):
            raise ValueError("anchor commitment path must be outside the resolved store directory")

        self._anchor_signing_key: bytes | None = None
        if anchor_signing_key is not None:
            seed = _require_32b_key(anchor_signing_key, "anchor_signing_key")
            derived_pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            if anchor_public_key is not None and _require_32b_key(anchor_public_key, "anchor_public_key") != derived_pub:
                raise ValueError("anchor_public_key does not match anchor_signing_key")
            self._anchor_signing_key = seed
            self.anchor_public_key = derived_pub
        elif anchor_public_key is not None:
            self.anchor_public_key = _require_32b_key(anchor_public_key, "anchor_public_key")
        else:
            seed = _load_or_create_offstore_anchor_seed(self.anchor_dir / "anchor.key")
            self._anchor_signing_key = seed
            self.anchor_public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )

        has_crystals = self.crystals_path.exists() or os.path.islink(self.crystals_path)
        has_erasures = self.erasures_path.exists() or os.path.islink(self.erasures_path)
        has_anchor = self.anchor_path.exists() or os.path.islink(self.anchor_path)
        if not has_crystals and not has_erasures and not has_anchor:
            if not create:
                raise CrystalRollbackError("crystal store and off-store anchor do not exist")
            if self._anchor_signing_key is None:
                raise CrystalVerificationError("cannot initialize a new store without anchor_signing_key")
            genesis = compute_crystal_set_commitment(
                [],
                self.tenant_hash,
                signing_key=self._anchor_signing_key,
                erasures=[],
            )
            _write_json_atomic(self.crystals_path, [], mode=0o600)
            _write_json_atomic(self.erasures_path, [], mode=0o600)
            _write_json_atomic(self.anchor_path, genesis, mode=0o600)

    def load_envelopes(self) -> list[dict[str, Any]]:
        data = _read_json_nofollow(self.crystals_path)
        if data is None:
            raise CrystalRollbackError(f"missing crystal store file: {self.crystals_path}")
        if not isinstance(data, list):
            raise CrystalVerificationError("crystals.json must contain a JSON list")
        return data

    def load_erasures(self) -> list[dict[str, Any]]:
        data = _read_json_nofollow(self.erasures_path)
        if data is None:
            return []
        if not isinstance(data, list):
            raise CrystalVerificationError("erasures.json must contain a JSON list")
        return data

    def load_anchor(self) -> dict[str, Any] | None:
        if os.path.islink(self.anchor_path) or os.path.islink(self.anchor_dir):
            raise CrystalVerificationError("refusing symlinked off-store anchor location")
        if self.anchor_path.resolve().is_relative_to(self.store_dir):
            raise CrystalRollbackError("anchor path points inside store directory")
        data = _read_json_nofollow(self.anchor_path)
        if data is None:
            return None
        if not isinstance(data, dict):
            raise CrystalRollbackError("off-store anchor commitment must be a JSON object")
        return data

    @staticmethod
    def _progress_key(commitment: dict[str, Any]) -> tuple[int, int]:
        count = int(commitment.get("count", 0))
        erasure_count = int(commitment.get("erasure_count", 0))
        revision = int(commitment.get("revision", count + erasure_count))
        return (revision, erasure_count)

    def _verify_current(self, *, anchor_public_key: bytes | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any] | None, list[bytes]]:
        envelopes = self.load_envelopes()
        erasures = self.load_erasures()
        commitment = self.load_anchor()
        if commitment is None and self.require_anchor:
            raise CrystalRollbackError(
                f"missing off-store anchor commitment at {self.anchor_path}; failing closed"
            )
        plaintexts = verify_and_unseal_crystal_set(
            envelopes,
            self.key,
            self.tenant_hash,
            expected_commitment=commitment,
            anchor_public_key=(anchor_public_key or self.anchor_public_key),
            erasures=erasures,
            require_anchor=self.require_anchor,
        )
        return envelopes, erasures, commitment, plaintexts

    def verify_and_unseal(self, *, anchor_public_key: bytes | None = None) -> list[bytes]:
        """Verify off-store anchor, erasure bindings, lineage, and unseal all crystals."""
        _, _, _, plaintexts = self._verify_current(anchor_public_key=anchor_public_key)
        return plaintexts

    def read_all(self) -> list[dict[str, Any]]:
        """Verify store integrity against off-store anchor and return unsealed records."""
        envelopes, _, _, plaintexts = self._verify_current()
        records: list[dict[str, Any]] = []
        for env, pt in zip(envelopes, plaintexts):
            records.append({
                "crystal_id": env["crystal_id"],
                "parent_crystal_id": env.get("parent_crystal_id"),
                "created_at": env["created_at"],
                "metadata_public": dict(env.get("metadata_public") or {}),
                "plaintext": pt,
            })
        return records

    def append(
        self,
        content: str | bytes | dict[str, Any],
        *,
        metadata_public: dict[str, Any] | None = None,
        sign_envelope: bool = True,
        client_signing_key: bytes | None = None,
    ) -> dict[str, Any]:
        """Seal, link, persist, and advance the off-store anchor commitment."""
        if self._anchor_signing_key is None:
            raise CrystalVerificationError("anchor_signing_key is required for store writes")
        if not isinstance(sign_envelope, bool):
            raise ValueError("sign_envelope must be a boolean")
        envelopes, erasures, prev_commitment, _ = self._verify_current()
        parent_id = envelopes[-1]["crystal_id"] if envelopes else None
        env = seal_crystal(
            content,
            self.key,
            self.tenant_id,
            parent_crystal_id=parent_id,
            metadata_public=metadata_public,
            cipher=self.cipher,
            kek_version=self.kek_version,
        )
        if sign_envelope:
            signer = client_signing_key or self._anchor_signing_key
            env = sign_crystal_envelope(env, signer)
        new_envelopes = envelopes + [env]
        new_commitment = compute_crystal_set_commitment(
            new_envelopes,
            self.tenant_hash,
            signing_key=self._anchor_signing_key,
            erasures=erasures,
        )
        if prev_commitment is not None and self._progress_key(new_commitment) <= self._progress_key(prev_commitment):
            raise CrystalRollbackError("refusing non-monotonic anchor progression on append")
        _write_json_atomic(self.crystals_path, new_envelopes, mode=0o600)
        _write_json_atomic(self.anchor_path, new_commitment, mode=0o600)
        return env

    def erase(
        self,
        crystal_id: str | None = None,
        *,
        erasure_class: str = "access_control_and_ciphertext_purge",
        erase_descendants: bool = False,
    ) -> list[dict[str, Any]]:
        """Erase the tail (or suffix from ``crystal_id``), record tombstones, and advance the off-store anchor."""
        if self._anchor_signing_key is None:
            raise CrystalVerificationError("anchor_signing_key is required for store erasures")
        if not isinstance(erase_descendants, bool):
            raise ValueError("erase_descendants must be a boolean")
        envelopes, erasures, prev_commitment, _ = self._verify_current()
        if not envelopes:
            raise CrystalVerificationError("cannot erase from an empty crystal store")
        if crystal_id is None:
            idx = len(envelopes) - 1
        else:
            match = CRYSTAL_ID_RE.fullmatch(crystal_id) if isinstance(crystal_id, str) else None
            if not match:
                raise ValueError("crystal_id must be a 64-hex SHA-256 identifier")
            target_id = f"sha256:{match.group(1).lower()}"
            idx = next(
                (i for i, e in enumerate(envelopes) if str(e.get("crystal_id", "")).lower() == target_id),
                -1,
            )
            if idx < 0:
                raise ValueError(f"crystal_id not found in store: {crystal_id}")
            if idx != len(envelopes) - 1 and not erase_descendants:
                raise CrystalLineageError(
                    "erasing an interior crystal breaks linear parent_crystal_id lineage; pass erase_descendants=True to erase suffix"
                )
        victims = envelopes[idx:]
        remaining = envelopes[:idx]
        erased_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tombstones: list[dict[str, Any]] = []
        for victim in reversed(victims):
            tombstone: dict[str, Any] = {
                "crystal_id": str(victim["crystal_id"]).lower(),
                "erased_at": erased_at,
                "class": erasure_class,
            }
            meta = victim.get("metadata_public")
            if isinstance(meta, dict) and "slot" in meta:
                tombstone["slot"] = meta["slot"]
            tombstones.append(tombstone)
        new_erasures = erasures + tombstones
        new_commitment = compute_crystal_set_commitment(
            remaining,
            self.tenant_hash,
            signing_key=self._anchor_signing_key,
            erasures=new_erasures,
        )
        if prev_commitment is not None:
            prev_rev, prev_er = self._progress_key(prev_commitment)
            new_rev, new_er = self._progress_key(new_commitment)
            if new_er <= prev_er or new_rev < prev_rev:
                raise CrystalRollbackError("refusing non-monotonic anchor progression on erase")
        _write_json_atomic(self.crystals_path, remaining, mode=0o600)
        _write_json_atomic(self.erasures_path, new_erasures, mode=0o600)
        _write_json_atomic(self.anchor_path, new_commitment, mode=0o600)
        return tombstones

    def verify_third_party(
        self,
        signer_public_key: bytes | None = None,
        *,
        notarization: dict[str, Any] | None = None,
        notary_public_key: bytes | None = None,
        expected_highwater_digest: str | None = None,
        expected_min_count: int | None = None,
        pq_verifier=None,
        expected_pq_public_key: str | None = None,
    ) -> dict[str, Any]:
        """Run zero-KEK third-party audit against off-store anchor and erasure tombstones."""
        envelopes = self.load_envelopes()
        erasures = self.load_erasures()
        commitment = self.load_anchor()
        if commitment is None:
            raise CrystalRollbackError(f"missing off-store anchor commitment at {self.anchor_path}")
        return verify_crystal_set_third_party(
            envelopes,
            self.tenant_hash,
            expected_commitment=commitment,
            signer_public_key=(signer_public_key or self.anchor_public_key),
            notarization=notarization,
            notary_public_key=notary_public_key,
            expected_highwater_digest=expected_highwater_digest,
            expected_min_count=expected_min_count,
            erasures=erasures,
            pq_verifier=pq_verifier,
            expected_pq_public_key=expected_pq_public_key,
        )


def sign_context_notarization(
    context_digest: str,
    notary_private_key: bytes,
    *,
    notarized_at: str | None = None,
    notary_id: str = "wm-context-notary",
    highwater_count: int | None = None,
) -> dict[str, Any]:
    """Create and sign a wm.context-notarization receipt with a trusted Ed25519 notary key."""
    _require_crypto()
    if len(notary_private_key) != 32:
        raise ValueError("notary_private_key must be 32-byte Ed25519 seed")
    if not isinstance(context_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", context_digest):
        raise ValueError("context_digest must be sha256:<64 lowercase hex>")
    ts = notarized_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stmt: dict[str, Any] = {
        "kind": "wm.context-notarization",
        "version": 1,
        "notary_id": notary_id,
        "context_digest": context_digest,
        "notarized_at": ts,
    }
    if highwater_count is not None:
        stmt["highwater_count"] = int(highwater_count)
    canon = json.dumps(stmt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    priv = Ed25519PrivateKey.from_private_bytes(notary_private_key)
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sig_b64 = base64.urlsafe_b64encode(priv.sign(canon)).decode("ascii")
    stmt["sig"] = {
        "alg": "ed25519",
        "public_key": pub_hex,
        "value": sig_b64,
    }
    return stmt


def verify_crystal_set_third_party(
    crystals: list[dict[str, Any]],
    expected_tenant_hash: str,
    *,
    expected_commitment: dict[str, Any],
    signer_public_key: bytes,
    notarization: dict[str, Any] | None = None,
    notary_public_key: bytes | None = None,
    expected_highwater_digest: str | None = None,
    expected_min_count: int | None = None,
    erasures: list[dict[str, Any]] | None = None,
    pq_verifier=None,
    expected_pq_public_key: str | None = None,
) -> dict[str, Any]:
    """Zero-knowledge third-party verifier (Level L5) for an ordered crystal set.

    Verifies all 9 storage-level integrity properties (T1-T9) WITHOUT the client's
    32-byte KEK (plaintext remains completely unobservable) and WITHOUT contacting
    the storage operator:
      - T1 (tamper): recomputes crystal_id = sha256(id_kek_version_be32 || nonce || ciphertext)
        and verifies Ed25519 client_sig over canonical envelope bytes.
      - T2 (truncate), T3 (delete_middle), T4 (reorder), T7 (rollback_replay):
        verifies unbroken parent_crystal_id DAG from genesis through head_crystal_id,
        no duplicate IDs, and ordered_crystal_ids_digest match.
      - T5 (forge): requires every crystal envelope to carry a valid Ed25519 client_sig
        matching ``signer_public_key`` (and fail-closed PQ verification if hybrid).
      - T6 (cross_replay): verifies envelope.tenant_hash == expected_tenant_hash.
      - T8 (metadata_tamper): covered by canonical envelope Ed25519 client_sig.
      - T9 (snapshot_rollback): verifies Ed25519 signature on ``expected_commitment``,
        optional ``expected_highwater_digest`` / ``expected_min_count``, and optional
        cryptographically signed external ``notarization`` receipt verified against
        ``notary_public_key``.
    """
    _require_crypto()
    if len(signer_public_key) != 32:
        raise ValueError("signer_public_key must be 32-byte raw Ed25519 public key")
    expected_pub_hex = signer_public_key.hex().lower()

    if not isinstance(expected_commitment, dict) or expected_commitment.get("kind") != "wm.crystal-set-commitment":
        raise CrystalRollbackError("invalid or missing crystal-set commitment")
    sig_obj = expected_commitment.get("sig")
    if not isinstance(sig_obj, dict) or sig_obj.get("alg") != "ed25519":
        raise CrystalRollbackError("anchor commitment is unsigned or uses unsupported alg")
    if str(sig_obj.get("public_key") or "").lower() != expected_pub_hex:
        raise CrystalRollbackError("anchor commitment public_key does not match signer_public_key")
    unsigned_comm = {
        k: v for k, v in expected_commitment.items()
        if k not in ("sig", "commitment_digest")
    }
    canon_comm = json.dumps(unsigned_comm, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    computed_comm_digest = "sha256:" + hashlib.sha256(canon_comm).hexdigest()
    if expected_commitment.get("commitment_digest") and expected_commitment.get("commitment_digest") != computed_comm_digest:
        raise CrystalRollbackError("anchor commitment_digest mismatch")
    try:
        pub = Ed25519PublicKey.from_public_bytes(signer_public_key)
        sig_str = str(sig_obj.get("value") or "")
        raw_sig = base64.urlsafe_b64decode(sig_str + "=" * (-len(sig_str) % 4))
        pub.verify(raw_sig, canon_comm)
    except Exception as exc:
        raise CrystalRollbackError(f"anchor commitment signature invalid: {exc}") from exc

    if expected_commitment.get("tenant_hash") != expected_tenant_hash:
        raise CrystalContextError("anchor commitment tenant_hash mismatch")

    _check_erasure_binding(
        expected_commitment,
        erasures,
        [str(c.get("crystal_id", "")).lower() for c in crystals if isinstance(c, dict)],
        "crystal set (third-party)",
    )

    if expected_highwater_digest is not None and computed_comm_digest != expected_highwater_digest:
        raise CrystalRollbackError(
            f"commitment digest {computed_comm_digest} does not match expected high-water digest {expected_highwater_digest}"
        )
    if expected_min_count is not None and int(expected_commitment.get("count", 0)) < int(expected_min_count):
        raise CrystalRollbackError(
            f"commitment count {expected_commitment.get('count')} is below high-water minimum {expected_min_count}"
        )

    notarized_verified = False
    if notarization is not None:
        wrapper = notarization if isinstance(notarization, dict) else {}
        stmt = notarization.get("receipt") or notarization.get("notarization") or notarization
        if not isinstance(stmt, dict) or stmt.get("kind") != "wm.context-notarization":
            raise CrystalRollbackError("invalid notarization receipt")
        if stmt.get("context_digest") != computed_comm_digest:
            raise CrystalRollbackError(
                f"notarization context_digest {stmt.get('context_digest')} != commitment {computed_comm_digest}"
            )
        wrapper_digest = wrapper.get("notarization_digest", wrapper.get("digest"))
        if wrapper_digest is not None:
            receipt_digest = "sha256:" + hashlib.sha256(
                _canonical_receipt_bytes({k: v for k, v in stmt.items() if k != "sig"})
            ).hexdigest()
            if wrapper_digest != receipt_digest:
                raise CrystalVerificationError("notarization_digest does not match signed receipt")
        if type(stmt.get("version")) is not int or stmt.get("version") != 1:
            raise CrystalVerificationError("unsupported notarization version")
        if notary_public_key is None or len(notary_public_key) != 32:
            raise CrystalVerificationError(
                "notarization verification requires a trusted 32-byte Ed25519 notary_public_key (fail-closed)"
            )
        notary_sig = stmt.get("sig")
        if not isinstance(notary_sig, dict) or notary_sig.get("alg") != "ed25519":
            raise CrystalVerificationError("notarization receipt is unsigned or uses unsupported signature algorithm")
        expected_notary_hex = notary_public_key.hex().lower()
        if notary_sig.get("alg") != "ed25519":
            raise CrystalVerificationError("notarization receipt uses unsupported signature algorithm")
        # receipt-api emits sig.key as did:key; the local helper emits raw hex
        # in sig.public_key. Both are accepted only when they resolve to the
        # externally pinned key. Never treat the carried identity as authority.
        carried_key = notary_sig.get("public_key")
        carried_did = notary_sig.get("key")
        if carried_key is not None:
            if str(carried_key).lower() != expected_notary_hex:
                raise CrystalVerificationError("notarization public_key does not match trusted notary_public_key")
            if carried_did is not None:
                try:
                    did_raw = _ed25519_did_key_bytes(str(carried_did))
                except Exception as exc:
                    raise CrystalVerificationError(f"invalid notarization did:key: {exc}") from exc
                if did_raw != notary_public_key:
                    raise CrystalVerificationError("notarization did:key does not match trusted notary_public_key")
        elif carried_did is not None:
            try:
                did_raw = _ed25519_did_key_bytes(str(carried_did))
            except Exception as exc:
                raise CrystalVerificationError(f"invalid notarization did:key: {exc}") from exc
            if did_raw != notary_public_key:
                raise CrystalVerificationError("notarization did:key does not match trusted notary_public_key")
            if stmt.get("issuer") != carried_did:
                raise CrystalVerificationError("notarization issuer does not match signature did:key")
        else:
            raise CrystalVerificationError("notarization signature is missing key identity")
        unsigned_stmt = {k: v for k, v in stmt.items() if k != "sig"}
        try:
            canon_stmt = _canonical_receipt_bytes(unsigned_stmt)
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise CrystalVerificationError(f"invalid canonical notarization statement: {exc}") from exc
        try:
            notary_pub = Ed25519PublicKey.from_public_bytes(notary_public_key)
            notary_sig_str = str(notary_sig.get("value") or "")
            raw_notary_sig = base64.urlsafe_b64decode(notary_sig_str + "=" * (-len(notary_sig_str) % 4))
            notary_pub.verify(raw_notary_sig, canon_stmt)
        except Exception as exc:
            raise CrystalVerificationError(f"notarization signature invalid: {exc}") from exc
        if "highwater_count" in stmt and int(expected_commitment.get("count", 0)) < int(stmt["highwater_count"]):
            raise CrystalRollbackError("commitment count is below notarized highwater_count")
        notarized_verified = True

    seen_ids: set[str] = set()
    for idx, env in enumerate(crystals):
        if not isinstance(env, dict):
            raise CrystalVerificationError(f"crystal at index {idx} is not an object")
        if env.get("tenant_hash") != expected_tenant_hash:
            raise CrystalContextError(
                f"cross-context crystal replay at index {idx}: tenant_hash {env.get('tenant_hash')} != {expected_tenant_hash}"
            )
        for field in ("crystal_id", "tenant_hash", "cipher", "nonce", "ciphertext", "created_at"):
            if field not in env:
                raise CrystalVerificationError(f"malformed envelope at index {idx}: missing field {field!r}")

        env_sig = env.get("client_sig")
        if not isinstance(env_sig, dict):
            raise CrystalVerificationError(f"forged or unsigned crystal at index {idx}: missing client_sig")
        env_alg = str(env_sig.get("alg") or "")
        if env_alg not in SUPPORTED_CLIENT_SIG_ALGS:
            raise CrystalVerificationError(f"unsupported client_sig alg at index {idx}: {env_alg!r}")
        if expected_pq_public_key and env_alg != "ed25519+ml-dsa-65":
            raise CrystalVerificationError(f"crystal at index {idx} does not meet required hybrid signature profile")
        if env_alg == "ed25519+ml-dsa-65":
            if pq_verifier is None or not expected_pq_public_key:
                raise CrystalVerificationError(
                    f"crystal at index {idx} uses hybrid PQ profile without explicit pq_verifier and expected_pq_public_key"
                )
            if str(env_sig.get("pq_public_key") or "") != expected_pq_public_key:
                raise CrystalVerificationError(f"crystal at index {idx} pq_public_key mismatch")
        if str(env_sig.get("public_key") or "").lower() != expected_pub_hex:
            raise CrystalVerificationError(
                f"crystal at index {idx} signed by unexpected key {env_sig.get('public_key')}"
            )
        try:
            verify_crystal_client_sig(env, pq_verifier=pq_verifier)
        except ValueError as exc:
            raise CrystalVerificationError(f"crystal signature verification failed at index {idx}: {exc}") from exc

        nonce = base64.urlsafe_b64decode(env["nonce"])
        ciphertext = base64.urlsafe_b64decode(env["ciphertext"])
        kek_version = env.get("kek_version")
        id_kek_version = env.get("id_kek_version", kek_version)
        expected_id = compute_crystal_id(ciphertext, nonce=nonce, id_kek_version=id_kek_version)
        cid = str(env["crystal_id"]).lower()
        if cid != expected_id.lower():
            raise CrystalVerificationError(
                f"crystal content-address verification failed at index {idx}: {cid} != {expected_id}"
            )
        if cid in seen_ids:
            raise CrystalLineageError(f"duplicate crystal_id at index {idx}: {cid}")
        seen_ids.add(cid)

        parent = env.get("parent_crystal_id")
        if idx == 0:
            if parent is not None:
                raise CrystalLineageError(f"genesis crystal at index 0 has non-null parent_crystal_id: {parent}")
        else:
            prev_id = str(crystals[idx - 1]["crystal_id"]).lower()
            if str(parent or "").lower() != prev_id:
                raise CrystalLineageError(
                    f"lineage link broken at index {idx}: parent_crystal_id {parent} != previous {prev_id}"
                )

    exp_count = int(expected_commitment.get("count", 0))
    if len(crystals) < exp_count:
        raise CrystalRollbackError(
            f"store rollback or truncation detected: store has {len(crystals)} crystals, anchor committed to {exp_count}"
        )
    prefix_ids = [str(c["crystal_id"]).lower() for c in crystals[:exp_count]]
    actual_digest = "sha256:" + hashlib.sha256("\n".join(prefix_ids).encode("utf-8")).hexdigest()
    exp_head = expected_commitment.get("head_crystal_id")
    actual_head = prefix_ids[-1] if prefix_ids else None
    if (exp_head or None) != actual_head:
        raise CrystalRollbackError(f"anchored head mismatch: expected {exp_head}, found {actual_head}")
    if expected_commitment.get("ordered_crystal_ids_digest") != actual_digest:
        raise CrystalRollbackError("ordered_crystal_ids_digest mismatch against anchor commitment")

    return {
        "verified": True,
        "level": "L5-third-party-zero-knowledge",
        "count": len(crystals),
        "head_crystal_id": actual_head,
        "tenant_hash": expected_tenant_hash,
        "signer_public_key": expected_pub_hex,
        "commitment_digest": computed_comm_digest,
        "notarized": notarized_verified,
    }


def rotate_crystal_kek(
    crystal_envelope: dict[str, Any],
    old_kek: bytes,
    new_kek: bytes,
    new_kek_version: int,
    *,
    ed25519_private_key: bytes | None = None,
    pq_alg: str | None = None,
    pq_public_key_b64: str | None = None,
    pq_sig_b64: str | None = None,
    pq_verifier=None,
) -> dict[str, Any]:
    """Re-wrap a crystal's per-crystal DEK under a new KEK version without changing crystal_id (I2).

    Signed Ed25519 envelopes can be rotated with the matching signer seed. Hybrid
    envelopes are refused until a callback API can sign the post-wrap canonical bytes.
    """
    if isinstance(new_kek_version, bool) or not isinstance(new_kek_version, int) or new_kek_version < 1:
        raise ValueError("new_kek_version must be a positive integer")
    old_ver = crystal_envelope.get("kek_version")
    wrapped = crystal_envelope.get("wrapped_dek")
    if old_ver is None or wrapped is None:
        raise ValueError("crystal envelope does not carry a wrapped per-crystal DEK")
    cipher_norm = _normalize_cipher(crystal_envelope["cipher"])
    nonce = base64.urlsafe_b64decode(crystal_envelope["nonce"])
    ciphertext = base64.urlsafe_b64decode(crystal_envelope["ciphertext"])
    id_kek_version = crystal_envelope.get("id_kek_version", old_ver)
    expected_id = compute_crystal_id(ciphertext, nonce=nonce, id_kek_version=id_kek_version)
    if crystal_envelope["crystal_id"].lower() != expected_id.lower():
        raise ValueError("cannot rotate KEK on an envelope failing content-address verification")

    existing_sig = crystal_envelope.get("client_sig")
    if existing_sig is not None:
        verify_crystal_client_sig(crystal_envelope, pq_verifier=pq_verifier)
        if existing_sig.get("alg") == "ed25519+ml-dsa-65":
            raise ValueError("hybrid KEK rotation is unsupported until a PQ signer callback can sign the updated envelope")
        if ed25519_private_key is None:
            raise ValueError(
                "rotating KEK on a signed crystal envelope requires ed25519_private_key to re-sign updated wrapped_dek"
            )
        if len(ed25519_private_key) != 32:
            raise ValueError("ed25519_private_key must be 32 bytes")
        priv = Ed25519PrivateKey.from_private_bytes(ed25519_private_key)
        pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex().lower()
        if str(existing_sig.get("public_key") or "").lower() != pub_hex:
            raise ValueError("ed25519_private_key does not match existing envelope client_sig public_key")

    dek = unwrap_crystal_dek(wrapped, old_kek, crystal_envelope["crystal_id"], int(old_ver), cipher=cipher_norm)
    updated = dict(crystal_envelope)
    updated["id_kek_version"] = int(id_kek_version)
    updated["kek_version"] = int(new_kek_version)
    updated["wrapped_dek"] = wrap_crystal_dek(
        dek, new_kek, crystal_envelope["crystal_id"], int(new_kek_version), cipher=cipher_norm
    )
    if existing_sig is not None and ed25519_private_key is not None:
        updated = sign_crystal_envelope(
            updated,
            ed25519_private_key,
            pq_alg=pq_alg,
            pq_public_key_b64=pq_public_key_b64,
            pq_sig_b64=pq_sig_b64,
        )
    return updated


def destroy_crystal_dek(crystal_envelope: dict[str, Any]) -> dict[str, Any]:
    """Scrub a crystal envelope copy's wrapped DEK (`wrapped_dek=None, dek_destroyed=True`) (I2/I3).

    Scope note: This renders the returned envelope copy undecryptable because its per-crystal
    wrapped DEK has been removed. Any pre-scrub envelope copy or off-box backup snapshot
    retaining ``wrapped_dek`` remains decryptable if the holder still possesses the KEK.
    """
    if crystal_envelope.get("wrapped_dek") is None and "kek_version" not in crystal_envelope:
        raise ValueError("crystal envelope does not use per-crystal DEK wrapping")
    erased = dict(crystal_envelope)
    erased["wrapped_dek"] = None
    erased["dek_destroyed"] = True
    return erased


def push_crystal(
    crystal_envelope: dict[str, Any],
    api_url: str = "https://api.whitemagic.dev",
    *, auth_token: str,
) -> dict[str, Any]:
    """Store sealed Memory Crystal envelope on remote gateway (requires auth/session pass)."""
    target = _require_https_api(api_url) + "/crystals"
    data = json.dumps(crystal_envelope).encode("utf-8")
    try:
        with _authenticated_request(target, method="POST", auth_token=auth_token, data=data, content_type=True) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"HTTP {e.code}: redirect refused") from None
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def pull_crystal(
    crystal_id: str,
    *,
    auth_token: str,
    api_url: str = "https://api.whitemagic.dev",
) -> dict[str, Any]:
    """Fetch a crystal from the authenticated owner's server-derived scope."""
    match = CRYSTAL_ID_RE.fullmatch(crystal_id) if isinstance(crystal_id, str) else None
    if not match:
        raise ValueError("crystal ID must be a SHA-256 hex digest, optionally prefixed by 'sha256:'")
    clean_id = match.group(1).lower()
    target = f"{_require_https_api(api_url)}/crystals/{clean_id}"
    try:
        with _authenticated_request(target, method="GET", auth_token=auth_token) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"HTTP {e.code}: redirect refused") from None
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def delete_crystal(
    crystal_id: str,
    *,
    auth_token: str,
    api_url: str = "https://api.whitemagic.dev",
) -> dict[str, Any]:
    """Erase a crystal in the authenticated owner's scope and return its signed erasure receipt (I3)."""
    match = CRYSTAL_ID_RE.fullmatch(crystal_id) if isinstance(crystal_id, str) else None
    if not match:
        raise ValueError("crystal ID must be a SHA-256 hex digest, optionally prefixed by 'sha256:'")
    clean_id = match.group(1).lower()
    target = f"{_require_https_api(api_url)}/crystals/{clean_id}"
    try:
        with _authenticated_request(target, method="DELETE", auth_token=auth_token) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"HTTP {e.code}: redirect refused") from None
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def pull_lineage(
    *,
    auth_token: str,
    api_url: str = "https://api.whitemagic.dev",
) -> list[dict[str, Any]]:
    """Fetch DAG lineage for the authenticated owner."""
    target = f"{_require_https_api(api_url)}/crystals/lineage"
    try:
        with _authenticated_request(target, method="GET", auth_token=auth_token) as res:
            doc = json.loads(res.read().decode("utf-8"))
            return doc.get("crystals", [])
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"HTTP {e.code}: redirect refused") from None
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def pull_erasures(
    *,
    auth_token: str,
    api_url: str = "https://api.whitemagic.dev",
) -> list[dict[str, Any]]:
    """Fetch reproducible list of signed crystal erasure receipts for the authenticated owner."""
    target = f"{_require_https_api(api_url)}/crystals/erasures"
    try:
        with _authenticated_request(target, method="GET", auth_token=auth_token) as res:
            doc = json.loads(res.read().decode("utf-8"))
            return doc.get("erasures", [])
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"HTTP {e.code}: redirect refused") from None
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def fetch_owner_locator(*, auth_token: str, api_url: str = "https://api.whitemagic.dev") -> str:
    """Fetch the registry-mapped locator after explicit owner authentication."""
    target = f"{_require_https_api(api_url)}/crystals/owner-locator"
    try:
        with _authenticated_request(target, method="GET", auth_token=auth_token) as res:
            doc = json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise RuntimeError(f"HTTP {e.code}: redirect refused") from None
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e
    locator = doc.get("owner_locator") if isinstance(doc, dict) else None
    if not isinstance(locator, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", locator):
        raise RuntimeError("gateway returned an invalid owner locator")
    return locator


def _token_from_inputs(token_env: str, token_file: str | None) -> str:
    if token_file:
        fd = os.open(
            token_file,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("token file must be a regular non-symlink file")
            if os.name == "posix" and st.st_mode & 0o077:
                raise ValueError("token file permissions must be 0600 or stricter")
            if st.st_size > 4096:
                raise ValueError("token file exceeds 4096 bytes")
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                fd = -1
                raw_token = stream.read(4097)
                if len(raw_token.encode("utf-8")) > 4096:
                    raise ValueError("token file exceeds 4096 bytes")
                token = raw_token.strip()
        finally:
            if fd >= 0:
                os.close(fd)
    else:
        token = os.environ.get(token_env, "")
    if not token:
        raise ValueError(f"credential unavailable; set {token_env} or use --token-file")
    return token


def main():
    ap = argparse.ArgumentParser(description="Client-encrypted WhiteMagic Memory Crystal utility")
    sub = ap.add_subparsers(dest="command")

    # genkey
    gen_cmd = sub.add_parser("genkey", help="Generate a random 32-byte crystal key")
    gen_cmd.add_argument("--out", default="", help="Save key to binary file")

    # seal
    seal_cmd = sub.add_parser("seal", help="Seal memory content into an encrypted crystal envelope")
    seal_cmd.add_argument("--content", help="Plaintext content string")
    seal_cmd.add_argument("--file", help="Path to plaintext file")
    seal_cmd.add_argument("--key", help="Hex-encoded 32-byte key or key file path", required=True)
    seal_cmd.add_argument("--kek-version", type=int, default=None, help="Optional KEK version (>=1) to bind cellId and wrap a per-crystal DEK")
    seal_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")
    seal_cmd.add_argument("--token-env", default="WM_CRYSTAL_TOKEN", help="Environment variable containing bearer credential")
    seal_cmd.add_argument("--token-file", help="Protected credential file (0600 or stricter)")
    seal_cmd.add_argument("--parent", help="Parent crystal ID (for chain DAG)", default=None)
    seal_cmd.add_argument("--cipher", choices=["AES-256-GCM", "ChaCha20-Poly1305"], default="AES-256-GCM")
    seal_cmd.add_argument("--out", help="Output JSON envelope file")

    # unseal
    unseal_cmd = sub.add_parser("unseal", help="Decrypt and verify a crystal envelope")
    unseal_cmd.add_argument("--envelope", help="Path to crystal envelope JSON", required=True)
    unseal_cmd.add_argument("--key", help="Hex-encoded 32-byte key or key file path", required=True)

    # push
    push_cmd = sub.add_parser("push", help="Push sealed crystal to remote gateway")
    push_cmd.add_argument("--envelope", help="Path to crystal envelope JSON", required=True)
    push_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")
    push_cmd.add_argument(
        "--token-env",
        default="WM_CRYSTAL_TOKEN",
        help="environment variable containing the API key or session pass (default: WM_CRYSTAL_TOKEN)",
    )
    push_cmd.add_argument("--token-file", help="Protected credential file (0600 or stricter)")

    # pull
    pull_cmd = sub.add_parser("pull", help="Pull crystal envelope from authenticated owner scope")
    pull_cmd.add_argument("--id", help="Crystal ID (sha256:... or hex)", required=True)
    pull_cmd.add_argument("--token-env", default="WM_CRYSTAL_TOKEN", help="Environment variable containing bearer credential")
    pull_cmd.add_argument("--token-file", help="Protected credential file (0600 or stricter)")
    pull_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")
    pull_cmd.add_argument("--out", help="Save pulled envelope to JSON file")

    # delete / forget
    del_cmd = sub.add_parser("delete", help="Erase a crystal in the authenticated owner's scope and emit a signed receipt")
    del_cmd.add_argument("--id", help="Crystal ID (sha256:... or hex)", required=True)
    del_cmd.add_argument("--token-env", default="WM_CRYSTAL_TOKEN", help="Environment variable containing bearer credential")
    del_cmd.add_argument("--token-file", help="Protected credential file (0600 or stricter)")
    del_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")

    # lineage
    lineage_cmd = sub.add_parser("lineage", help="Fetch crystal lineage DAG for authenticated owner")
    lineage_cmd.add_argument("--token-env", default="WM_CRYSTAL_TOKEN", help="Environment variable containing bearer credential")
    lineage_cmd.add_argument("--token-file", help="Protected credential file (0600 or stricter)")
    lineage_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")

    locator_cmd = sub.add_parser("owner-locator", help="Fetch authenticated server-assigned owner locator")
    locator_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")
    locator_cmd.add_argument("--token-env", default="WM_CRYSTAL_TOKEN", help="Environment variable containing bearer credential")
    locator_cmd.add_argument("--token-file", help="Protected credential file (0600 or stricter)")

    args = ap.parse_args()

    def resolve_key(key_str: str) -> bytes:
        if os.path.isfile(key_str):
            with open(key_str, "rb") as key_file:
                raw = key_file.read()
            if len(raw) == 32:
                return raw
            raw_text = raw.strip()
            if len(raw_text) == 64:
                return bytes.fromhex(raw_text.decode("ascii"))
        if len(key_str) == 64:
            return bytes.fromhex(key_str)
        if len(key_str.encode("utf-8")) == 32:
            return key_str.encode("utf-8")
        raise ValueError("key must be 32 bytes or 64 hex characters")

    if args.command == "genkey":
        key = generate_key()
        if args.out:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            print(f"Key written to {args.out}")
        else:
            print(key.hex())

    elif args.command == "seal":
        key = resolve_key(args.key)
        if args.file:
            content = open(args.file, "rb").read()
        elif args.content:
            content = args.content
        else:
            content = sys.stdin.read()
        token = _token_from_inputs(args.token_env, args.token_file)
        locator = fetch_owner_locator(auth_token=token, api_url=args.api)
        envelope = seal_crystal(
            content=content,
            key=key,
            tenant_id="owner-locator",
            parent_crystal_id=args.parent,
            cipher=args.cipher,
            owner_locator=locator,
            kek_version=args.kek_version,
        )
        out_json = json.dumps(envelope, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_json + "\n")
            print(f"Sealed crystal {envelope['crystal_id']} saved to {args.out}")
        else:
            print(out_json)

    elif args.command == "unseal":
        key = resolve_key(args.key)
        envelope = json.loads(open(args.envelope, "r", encoding="utf-8").read())
        plaintext = unseal_crystal(envelope, key)
        sys.stdout.buffer.write(plaintext)
        if not plaintext.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")

    elif args.command == "push":
        envelope = json.loads(open(args.envelope, "r", encoding="utf-8").read())
        token = _token_from_inputs(args.token_env, args.token_file)
        res = push_crystal(envelope, api_url=args.api, auth_token=token)
        print(json.dumps(res, indent=2))

    elif args.command == "pull":
        doc = pull_crystal(args.id, auth_token=_token_from_inputs(args.token_env, args.token_file), api_url=args.api)
        out_json = json.dumps(doc, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_json + "\n")
            print(f"Pulled crystal saved to {args.out}")
        else:
            print(out_json)

    elif args.command == "delete":
        res = delete_crystal(args.id, auth_token=_token_from_inputs(args.token_env, args.token_file), api_url=args.api)
        print(json.dumps(res, indent=2))

    elif args.command == "lineage":
        items = pull_lineage(auth_token=_token_from_inputs(args.token_env, args.token_file), api_url=args.api)
        print(json.dumps(items, indent=2))

    elif args.command == "owner-locator":
        print(fetch_owner_locator(auth_token=_token_from_inputs(args.token_env, args.token_file), api_url=args.api))

    else:
        ap.print_help()


if __name__ == "__main__":
    main()
