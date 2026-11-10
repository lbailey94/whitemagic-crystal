"""Tests for safe key handling across client instances and processes."""

import base64
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from whitemagic_crystal import CrystalClient, generate_key
from whitemagic_crystal.core import CrystalVerificationError, verify_crystal_client_sig


class TestKeyLifecycle(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop("WM_CRYSTAL_KEY", None)
        os.environ.pop("WM_CRYSTAL_SIGNING_KEY", None)
        self.addCleanup(self.env.stop)

    def test_requires_key_or_explicit_ephemeral_opt_in(self):
        with self.assertRaisesRegex(ValueError, "retained encryption key"):
            CrystalClient("demo")
        client = CrystalClient("demo", ephemeral=True)
        envelope = client.seal("local demo")
        self.assertEqual(client.unseal_text(envelope), "local demo")
        with self.assertRaises(CrystalVerificationError):
            CrystalClient("demo", ephemeral=True).unseal(envelope)
        with self.assertRaisesRegex(ValueError, "ephemeral"):
            CrystalClient("demo", ephemeral="false")

    def test_retained_key_recovers_in_fresh_process(self):
        key = generate_key()
        client = CrystalClient("demo", key=key)
        envelope = client.seal("fresh process recovery")
        env = os.environ.copy()
        env["WM_CRYSTAL_KEY"] = base64.b64encode(key).decode("ascii")
        code = (
            "import json,sys; from whitemagic_crystal import CrystalClient; "
            "e=json.load(sys.stdin); print(CrystalClient('demo').unseal_text(e))"
        )
        child = subprocess.run(
            [sys.executable, "-c", code], input=json.dumps(envelope),
            text=True, capture_output=True, env=env, check=True,
        )
        self.assertEqual(child.stdout.strip(), "fresh process recovery")

    def test_malformed_keys_fail_at_initialization(self):
        for invalid in (b"short", "bad!encoding", "a" * 10):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                CrystalClient("demo", key=invalid)
        os.environ["WM_CRYSTAL_KEY"] = "not base64!"
        with self.assertRaisesRegex(ValueError, "WM_CRYSTAL_KEY"):
            CrystalClient("demo")

    def test_optional_and_required_signatures(self):
        key = generate_key()
        plain = CrystalClient("demo", key=key)
        self.assertNotIn("client_sig", plain.seal("unsigned"))
        with self.assertRaisesRegex(ValueError, "sign=True"):
            plain.seal("unsigned", sign=True)
        with self.assertRaisesRegex(ValueError, "sign must"):
            plain.seal("unsigned", sign="true")
        signer = CrystalClient("demo", key=key, signing_key_hex=generate_key().hex())
        envelope = signer.seal("signed", sign=True)
        self.assertIn("client_sig", envelope)
        self.assertTrue(verify_crystal_client_sig(envelope))
        self.assertEqual(signer.unseal_text(envelope), "signed")
        altered = dict(envelope, created_at="2000-01-01T00:00:00Z")
        with self.assertRaises((ValueError, CrystalVerificationError)):
            signer.unseal(altered)
        self.assertNotIn("client_sig", signer.seal("deliberately unsigned", sign=False))

    def test_invalid_signing_seed_rejected(self):
        for bad in ("z" * 64, "00" * 31):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "Ed25519"):
                CrystalClient("demo", key=generate_key(), signing_key_hex=bad)


if __name__ == "__main__":
    unittest.main()
