"""Caller-pinned commitment checks, not a freshness or signer-authority oracle."""

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from whitemagic_crystal import (
    CrystalClient,
    LocalCrystalStore,
    compute_crystal_set_commitment,
    generate_key,
)
from whitemagic_crystal.core import CrystalContextError, CrystalRollbackError, CrystalVerificationError


class TestAnchoredSet(unittest.TestCase):
    def setUp(self):
        self.client = CrystalClient("tenant", key=generate_key())
        first = self.client.seal("one")
        second = self.client.seal("two", parent_id=first["crystal_id"])
        self.envelopes = [first, second]
        self.seed = generate_key()
        self.public_key = Ed25519PrivateKey.from_private_bytes(self.seed).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.anchor = compute_crystal_set_commitment(
            self.envelopes, self.client.tenant_hash, signing_key=self.seed
        )

    def verify(self, envelopes=None, anchor=None, key=None):
        return self.client.verify_set(
            self.envelopes if envelopes is None else envelopes,
            self.anchor if anchor is None else anchor,
            anchor_public_key=self.public_key if key is None else key,
        )

    def test_signed_prefix_and_valid_extension(self):
        self.assertTrue(self.verify())
        third = self.client.seal("three", parent_id=self.envelopes[-1]["crystal_id"])
        self.assertTrue(self.verify(envelopes=self.envelopes + [third]))

    def test_rejects_truncation_and_untrusted_or_missing_anchor(self):
        with self.assertRaises(CrystalRollbackError):
            self.verify(envelopes=self.envelopes[:1])
        with self.assertRaises(CrystalRollbackError):
            self.verify(key=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        unsigned = copy.deepcopy(self.anchor)
        unsigned.pop("sig")
        with self.assertRaises(CrystalRollbackError):
            self.verify(anchor=unsigned)

    def test_rejects_modified_anchor_and_invalid_schema(self):
        for field, value in (("count", -1), ("version", True), ("head_crystal_id", "sha256:" + "0" * 64)):
            anchor = copy.deepcopy(self.anchor)
            anchor[field] = value
            with self.subTest(field=field), self.assertRaises(CrystalRollbackError):
                self.verify(anchor=anchor)
        anchor = copy.deepcopy(self.anchor)
        anchor["sig"]["value"] = "A" * 88
        with self.assertRaises(CrystalRollbackError):
            self.verify(anchor=anchor)

    def test_rejects_wrong_tenant_and_ciphertext_tampering(self):
        other = CrystalClient("other", key=self.client.key)
        with self.assertRaises(CrystalContextError):
            other.verify_set(self.envelopes, self.anchor, anchor_public_key=self.public_key)
        changed = copy.deepcopy(self.envelopes)
        changed[0]["ciphertext"] = "AAAA"
        with self.assertRaises((ValueError, CrystalVerificationError)):
            self.verify(envelopes=changed)

    def test_local_crystal_store_auto_persists_offstore_anchor(self):
        import os
        import shutil
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            store_dir = root / "store"
            with patch.dict(os.environ, {"XDG_STATE_HOME": str(root / "xdg")}):
                store = LocalCrystalStore(store_dir, key=generate_key(), tenant_id="pkg-tenant")
                self.assertFalse(store.anchor_path.is_relative_to(store.store_dir))
                e1 = store.append("alpha", metadata_public={"slot": "k1"})
                snap = root / "snap"
                shutil.copytree(store_dir, snap)
                e2 = store.append("beta", metadata_public={"slot": "k2"})
                self.assertEqual([r["plaintext"] for r in store.read_all()], [b"alpha", b"beta"])

                # Snapshot rollback of store_dir is rejected automatically.
                shutil.rmtree(store_dir)
                shutil.copytree(snap, store_dir)
                with self.assertRaises(CrystalRollbackError):
                    store.read_all()

                # Erase e2 cleanly and reject pre-erasure resurrection.
                store.crystals_path.write_text(__import__("json").dumps([e1, e2]), encoding="utf-8")
                snap2 = root / "snap2"
                shutil.copytree(store_dir, snap2)
                store.erase(e2["crystal_id"])
                self.assertEqual([r["plaintext"] for r in store.read_all()], [b"alpha"])
                shutil.rmtree(store_dir)
                shutil.copytree(snap2, store_dir)
                with self.assertRaises(CrystalRollbackError):
                    store.read_all()


if __name__ == "__main__":
    unittest.main()
