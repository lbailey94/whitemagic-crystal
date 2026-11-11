"""Caller-pinned commitment checks, not a freshness or signer-authority oracle."""

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from whitemagic_crystal import CrystalClient, compute_crystal_set_commitment, generate_key
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


if __name__ == "__main__":
    unittest.main()
