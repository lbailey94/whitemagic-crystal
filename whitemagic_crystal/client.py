"""High-level Pythonic client for WhiteMagic Encrypted Memory Crystals."""

from __future__ import annotations

import base64
import os
from typing import Any

from .core import (
    CrystalContextError,
    CrystalLineageError,
    CrystalRollbackError,
    CrystalVerificationError,
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
    
    Guarantees:
      - Memory plaintext is sealed locally before transmission (AES-256-GCM / ChaCha20-Poly1305).
      - Zero unencrypted memory leaks to cloud or hosted relays.
      - Content-addressed tamper-evident cryptographic envelopes.
    """

    def __init__(
        self,
        tenant_id: str,
        auth_token: str | None = None,
        key: bytes | str | None = None,
        api_url: str = "https://mcp.whitemagic.dev",
        cipher: str = "AES-256-GCM",
        signing_key_hex: str | None = None,
    ):
        self.tenant_id = tenant_id
        self.auth_token = auth_token or os.getenv("WM_HOSTED_TOKEN") or ""
        self.api_url = api_url.rstrip("/")
        self.cipher = cipher
        self.signing_key_hex = signing_key_hex or os.getenv("WM_CRYSTAL_SIGNING_KEY")

        if key is None:
            raw_key_b64 = os.getenv("WM_CRYSTAL_KEY")
            if raw_key_b64:
                self.key = base64.b64decode(raw_key_b64)
            else:
                self.key = generate_key(cipher)
        elif isinstance(key, str):
            # Hex or base64
            try:
                self.key = bytes.fromhex(key)
            except ValueError:
                self.key = base64.b64decode(key)
        else:
            self.key = key

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
        sign: bool = True,
    ) -> dict[str, Any]:
        """Encrypt and seal memory plaintext into a cryptographic envelope."""
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
        if sign and self.signing_key_hex:
            envelope = sign_crystal_envelope(envelope, self.signing_key_hex)
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
        expected_root: str,
    ) -> bool:
        """Verify Merkle/hash commitment of a multi-crystal set."""
        computed_root = compute_crystal_set_commitment(envelopes)
        return computed_root == expected_root
