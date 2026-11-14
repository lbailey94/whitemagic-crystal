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
    CRYSTAL_ID_RE,
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
        api_url: str = "https://api.whitemagic.dev",
        cipher: str = "AES-256-GCM",
        signing_key_hex: str | None = None,
        *,
        ephemeral: bool = False,
        owner_locator: str | None = None,
    ):
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("tenant_id must be a nonempty string")
        if type(ephemeral) is not bool:
            raise ValueError("ephemeral must be a boolean")
        self.tenant_id = tenant_id
        self.auth_token = auth_token or os.getenv("WM_HOSTED_TOKEN") or ""
        self.api_url = api_url.rstrip("/")
        self.cipher = cipher
        if owner_locator is not None and (
            not isinstance(owner_locator, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", owner_locator) is None
        ):
            raise ValueError("owner_locator must be sha256:<64 lowercase hex> from authenticated bootstrap")
        self.owner_locator = owner_locator
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
        return self.owner_locator or compute_tenant_hash(self.tenant_id)

    def _check_context(self, envelope: Any) -> None:
        if not isinstance(envelope, dict):
            raise CrystalVerificationError("crystal envelope must be an object")
        if envelope.get("tenant_hash") != self.tenant_hash:
            raise CrystalContextError("crystal tenant_hash does not match this client")

    def _require_hosted_context(self) -> None:
        if not self.auth_token:
            raise ValueError("auth_token is required for remote API access")
        if self.owner_locator is None:
            raise ValueError("owner_locator is required for remote API access; fetch it through authenticated bootstrap")

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
        if sign is not None and type(sign) is not bool:
            raise ValueError("sign must be a boolean or None")
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
            owner_locator=self.owner_locator,
        )
        if sign is not False and self.signing_key_hex:
            envelope = sign_crystal_envelope(envelope, bytes.fromhex(self.signing_key_hex))
        return envelope

    def unseal(self, envelope: dict[str, Any]) -> bytes:
        """Decrypt and verify memory crystal envelope returning raw plaintext."""
        self._check_context(envelope)
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
        self._require_hosted_context()

        if isinstance(envelope_or_plaintext, dict) and "ciphertext" in envelope_or_plaintext:
            envelope = envelope_or_plaintext
        else:
            envelope = self.seal(envelope_or_plaintext, parent_id=parent_id, tags=tags)

        self._check_context(envelope)
        response = push_crystal(envelope, api_url=self.api_url, auth_token=self.auth_token)
        if (not isinstance(response, dict) or response.get("stored") is not True
                or response.get("crystal_id") != envelope.get("crystal_id")):
            raise CrystalVerificationError("gateway did not confirm storage of the requested crystal")
        return response

    def pull(self, crystal_id: str, auto_unseal: bool = True) -> tuple[dict[str, Any], bytes | None]:
        """Fetch a matching ID and context, optionally verifying and decrypting.

        With auto_unseal=False the labels are checked but the ciphertext and
        optional signature are not verified. The response is still untrusted.
        """
        self._require_hosted_context()
        requested = CRYSTAL_ID_RE.fullmatch(crystal_id) if isinstance(crystal_id, str) else None
        if requested is None:
            raise ValueError("crystal ID must be a SHA-256 hex digest, optionally prefixed by 'sha256:'")

        envelope = pull_crystal(
            crystal_id=crystal_id,
            auth_token=self.auth_token,
            api_url=self.api_url,
        )
        self._check_context(envelope)
        received_id = envelope.get("crystal_id")
        received = CRYSTAL_ID_RE.fullmatch(received_id) if isinstance(received_id, str) else None
        if received is None or received.group(1).lower() != requested.group(1).lower():
            raise CrystalVerificationError("gateway returned a different crystal ID")
        plaintext = self.unseal(envelope) if auto_unseal else None
        return envelope, plaintext

    def pull_text(self, crystal_id: str) -> tuple[dict[str, Any], str]:
        """Fetch and unseal as UTF-8 string."""
        envelope, raw = self.pull(crystal_id, auto_unseal=True)
        return envelope, raw.decode("utf-8") if raw else ""

    def delete(self, crystal_id: str) -> dict[str, Any]:
        """Delete an encrypted memory crystal from remote API."""
        self._require_hosted_context()

        return delete_crystal(
            crystal_id=crystal_id,
            auth_token=self.auth_token,
            api_url=self.api_url,
        )

    def lineage(self) -> list[dict[str, Any]]:
        """Fetch the gateway's lineage; the response does not prove completeness."""
        self._require_hosted_context()

        return pull_lineage(
            auth_token=self.auth_token,
            api_url=self.api_url,
        )

    def erasures(self) -> list[dict[str, Any]]:
        """Fetch gateway erasure records; the caller must verify them and their trust context."""
        self._require_hosted_context()

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
        erasures: list[dict[str, Any]] | None = None,
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
        base_keys = {
            "kind", "version", "spec", "tenant_hash", "count",
            "ordered_crystal_ids_digest", "head_crystal_id", "retrieved_at",
            "commitment_digest", "sig",
        }
        erasure_keys = {"erasure_count", "erased_crystal_ids_digest", "revision"}
        sig = expected_commitment.get("sig")
        count = expected_commitment.get("count")
        digest_pattern = r"sha256:[0-9a-f]{64}"
        present_keys = set(expected_commitment)
        if (
            present_keys not in (base_keys, base_keys | erasure_keys)
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
            expected_commitment=expected_commitment,
            anchor_public_key=anchor_public_key,
            erasures=erasures,
            require_anchor=True,
        )
        return True
