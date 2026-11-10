"""High-level Pythonic client for WhiteMagic Encrypted Memory Crystals."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from typing import Any

from .core import (
    CrystalContextError,
    CrystalLineageError,
    CrystalRollbackError,
    CrystalVerificationError,
    SPEC,
    compute_crystal_id,
    compute_crystal_set_commitment,
    compute_tenant_hash,
    delete_crystal,
    generate_key,
    pull_crystal,
    pull_erasures,
    pull_lineage,
    push_crystal,
    seal_crystal,
    sign_crystal_envelope,
    unseal_crystal,
    verify_and_unseal_crystal_set,
    verify_crystal_client_sig,
    verify_crystal_set_third_party,
)


class CrystalClient:
    """Sovereign client for client-side encrypted WhiteMagic Memory Crystals.
    
    Seals content locally before transmission. The caller is responsible for
    retaining the encryption key and protecting plaintext and key material.
    ``ephemeral=True`` creates a throwaway key only for an explicit local demo.
    """

    def __init__(
        self,
        tenant_id: str,
        auth_token: str | None = None,
        key: bytes | str | None = None,
        api_url: str = "https://mcp.whitemagic.dev",
        cipher: str = "AES-256-GCM",
        signing_key_hex: str | None = None,
        *,
        ephemeral: bool = False,
    ):
        self.tenant_id = tenant_id
        self.auth_token = auth_token or os.getenv("WM_HOSTED_TOKEN") or ""
        self.api_url = api_url.rstrip("/")
        self.cipher = cipher
        self.signing_key_hex = signing_key_hex or os.getenv("WM_CRYSTAL_SIGNING_KEY")
        if self.signing_key_hex:
            try:
                signing_key = bytes.fromhex(self.signing_key_hex)
            except ValueError as exc:
                raise ValueError("signing key must be a 32-byte Ed25519 seed encoded as hex") from exc
            if len(signing_key) != 32:
                raise ValueError("signing key must be a 32-byte Ed25519 seed encoded as hex")

        if key is None:
            raw_key_b64 = os.getenv("WM_CRYSTAL_KEY")
            if raw_key_b64:
                try:
                    self.key = base64.b64decode(raw_key_b64, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise ValueError("WM_CRYSTAL_KEY must be a base64-encoded 32-byte key") from exc
            elif ephemeral:
                self.key = generate_key(cipher)
            else:
                raise ValueError(
                    "A retained encryption key is required: pass key or set WM_CRYSTAL_KEY. "
                    "For a disposable local session only, pass ephemeral=True."
                )
        elif isinstance(key, str):
            # Hex or base64
            try:
                self.key = bytes.fromhex(key)
            except ValueError:
                try:
                    self.key = base64.b64decode(key, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise ValueError("key must be 32 bytes or a hex/base64 encoding of 32 bytes") from exc
        else:
            self.key = key
        if not isinstance(self.key, bytes) or len(self.key) != 32:
            raise ValueError("encryption key must be exactly 32 bytes")

    @property
    def key_base64(self) -> str:
        """Export current encryption key as base64 string."""
        return base64.b64encode(self.key).decode("ascii")

    @property
    def tenant_hash(self) -> str:
        """Deterministic tenant identity hash."""
        return compute_tenant_hash(self.tenant_id)

    def seal(
        self,
        plaintext: bytes | str | dict,
        parent_id: str | None = None,
        tags: list[str] | None = None,
        sign: bool | None = None,
    ) -> dict[str, Any]:
        """Seal locally; sign when configured unless sign=False.

        Explicit sign=True requires an Ed25519 signing key. An unsigned
        envelope provides no signer identity, even though AEAD authenticates
        its ciphertext to a holder of the symmetric key.
        """
        if sign is True and not self.signing_key_hex:
            raise ValueError("sign=True requires signing_key_hex or WM_CRYSTAL_SIGNING_KEY")
        metadata_public = {"tags": tags} if tags else None
        envelope = seal_crystal(
            content=plaintext,
            key=self.key,
            tenant_id=self.tenant_id,
            parent_crystal_id=parent_id,
            metadata_public=metadata_public,
            cipher=self.cipher,
        )
        envelope["id"] = envelope["crystal_id"]
        if sign is not False and self.signing_key_hex:
            envelope = sign_crystal_envelope(envelope, bytes.fromhex(self.signing_key_hex))
        return envelope

    def unseal(self, envelope: dict[str, Any]) -> bytes:
        """Decrypt and verify memory crystal envelope returning raw plaintext."""
        return unseal_crystal(crystal_envelope=envelope, key=self.key)

    def unseal_text(self, envelope: dict[str, Any]) -> str:
        """Decrypt and verify memory crystal envelope returning decoded UTF-8 string."""
        return self.unseal(envelope).decode("utf-8")

    def push(
        self,
        envelope_or_plaintext: dict[str, Any] | bytes | str,
        parent_id: str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Seal (if necessary) and store encrypted memory crystal to hosted vault."""
        if not self.auth_token:
            raise ValueError("auth_token is required to push to remote API")

        if isinstance(envelope_or_plaintext, dict) and "ciphertext" in envelope_or_plaintext:
            envelope = envelope_or_plaintext
        else:
            envelope = self.seal(envelope_or_plaintext, parent_id=parent_id, tags=tags)

        return push_crystal(envelope, api_url=self.api_url, auth_token=self.auth_token)

    def pull(self, crystal_id: str, auto_unseal: bool = True) -> tuple[dict[str, Any], bytes | None]:
        """Fetch encrypted crystal from remote API and optionally decrypt."""
        if not self.auth_token:
            raise ValueError("auth_token is required to pull from remote API")

        envelope = pull_crystal(
            crystal_id=crystal_id,
            auth_token=self.auth_token,
            api_url=self.api_url,
        )
        plaintext = self.unseal(envelope) if auto_unseal else None
        return envelope, plaintext

    def pull_text(self, crystal_id: str) -> tuple[dict[str, Any], str]:
        """Fetch and unseal as UTF-8 string."""
        envelope, raw = self.pull(crystal_id, auto_unseal=True)
        return envelope, raw.decode("utf-8") if raw else ""

    def delete(self, crystal_id: str) -> dict[str, Any]:
        """Delete an encrypted memory crystal from remote API."""
        if not self.auth_token:
            raise ValueError("auth_token is required to delete from remote API")

        return delete_crystal(
            crystal_id=crystal_id,
            auth_token=self.auth_token,
            api_url=self.api_url,
        )

    def lineage(self) -> list[dict[str, Any]]:
        """Fetch complete cryptographic ancestor-lineage for current tenant."""
        if not self.auth_token:
            raise ValueError("auth_token is required to fetch lineage")

        return pull_lineage(
            auth_token=self.auth_token,
            api_url=self.api_url,
        )

    def erasures(self) -> list[dict[str, Any]]:
        """Fetch verifiable cryptographic erasure certificates."""
        if not self.auth_token:
            raise ValueError("auth_token is required to fetch erasures")

        return pull_erasures(
            auth_token=self.auth_token,
            api_url=self.api_url,
        )

    def verify_set(
        self,
        envelopes: list[dict[str, Any]],
        expected_commitment: dict[str, Any],
        *,
        anchor_public_key: bytes,
    ) -> bool:
        """Check a set against an independently retained signed commitment.

        The caller must obtain a trusted Ed25519 public key and a current
        commitment out of band. Verifies the commitment's signed prefix,
        tenant, lineage and AEAD decryption; later valid records may extend
        the prefix. This cannot establish anchor freshness, issuer honesty,
        authorized signer identities, or metadata integrity on unsigned
        unversioned envelopes. Raises on failure and returns True on success.
        """
        if not isinstance(anchor_public_key, bytes) or len(anchor_public_key) != 32:
            raise ValueError("anchor_public_key must be a trusted 32-byte Ed25519 public key")
        if not isinstance(expected_commitment, dict):
            raise CrystalRollbackError("expected_commitment must be an independently retained signed commitment")
        expected_keys = {
            "kind", "version", "spec", "tenant_hash", "count",
            "ordered_crystal_ids_digest", "head_crystal_id", "retrieved_at",
            "commitment_digest", "sig",
        }
        sig = expected_commitment.get("sig")
        count = expected_commitment.get("count")
        digest_pattern = r"sha256:[0-9a-f]{64}"
        if (
            set(expected_commitment) != expected_keys
            or expected_commitment.get("kind") != "wm.crystal-set-commitment"
            or type(expected_commitment.get("version")) is not int
            or expected_commitment.get("version") != 1
            or expected_commitment.get("spec") != SPEC
            or type(count) is not int
            or count < 0
            or not isinstance(expected_commitment.get("retrieved_at"), str)
            or not re.fullmatch(digest_pattern, str(expected_commitment.get("ordered_crystal_ids_digest") or ""))
            or not re.fullmatch(digest_pattern, str(expected_commitment.get("commitment_digest") or ""))
            or (count == 0 and expected_commitment.get("head_crystal_id") is not None)
            or (count > 0 and not re.fullmatch(digest_pattern, str(expected_commitment.get("head_crystal_id") or "")))
            or not isinstance(sig, dict)
            or set(sig) != {"alg", "public_key", "value"}
            or sig.get("alg") != "ed25519"
            or sig.get("public_key") != anchor_public_key.hex()
            or not isinstance(sig.get("value"), str)
        ):
            raise CrystalRollbackError("malformed commitment or unexpected anchor identity")
        unsigned = {k: v for k, v in expected_commitment.items() if k not in ("sig", "commitment_digest")}
        canon = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if expected_commitment["commitment_digest"] != "sha256:" + hashlib.sha256(canon).hexdigest():
            raise CrystalRollbackError("commitment digest mismatch")
        verify_and_unseal_crystal_set(
            envelopes, self.key, self.tenant_hash,
            expected_commitment=expected_commitment, anchor_public_key=anchor_public_key,
        )
        return True
