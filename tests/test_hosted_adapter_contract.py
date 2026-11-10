"""Local contract tests; no hosted service or real credentials are used."""

import copy
import io
import json
import unittest
from unittest.mock import patch

from whitemagic_crystal import CrystalClient, fetch_owner_locator, generate_key, verify_crystal_client_sig
from whitemagic_crystal.adapters.generic import SessionMemoryManager
from whitemagic_crystal.core import CrystalContextError, CrystalVerificationError


class HostedClientContractTests(unittest.TestCase):
    def setUp(self):
        self.locator = "sha256:" + "a" * 64
        self.client = CrystalClient(
            "label", key=generate_key(), auth_token="synthetic-test-token",
            owner_locator=self.locator, signing_key_hex=generate_key().hex(),
        )

    def test_gateway_projected_signed_envelope_retains_signature(self):
        envelope = self.client.seal("synthetic")
        self.assertNotIn("id", envelope)
        self.assertEqual(envelope["tenant_hash"], self.locator)
        # receipt-api's MemoryCrystal.from_dict/to_dict persists these fields.
        fields = {"spec", "crystal_id", "parent_crystal_id", "tenant_hash", "cipher",
                  "nonce", "ciphertext", "size_bytes", "created_at", "metadata_public", "client_sig"}
        projected = {k: v for k, v in envelope.items() if k in fields}
        self.assertEqual(projected, envelope)
        self.assertTrue(verify_crystal_client_sig(projected))
        self.assertEqual(self.client.unseal_text(projected), "synthetic")

    def test_remote_operations_require_explicit_owner_bootstrap(self):
        client = CrystalClient("label", key=generate_key(), auth_token="synthetic-test-token")
        with patch("whitemagic_crystal.client.push_crystal") as push:
            with self.assertRaisesRegex(ValueError, "owner_locator"):
                client.push("synthetic")
            push.assert_not_called()
        with self.assertRaisesRegex(ValueError, "owner_locator"):
            client.pull("0" * 64)

    def test_explicit_bootstrap_parses_a_gateway_locator_without_network(self):
        with patch("whitemagic_crystal.core._authenticated_request", return_value=io.BytesIO(json.dumps({"owner_locator": self.locator}).encode())) as request:
            self.assertEqual(fetch_owner_locator(auth_token="synthetic-test-token"), self.locator)
            self.assertEqual(request.call_args.args[0], "https://api.whitemagic.dev/crystals/owner-locator")
        with patch("whitemagic_crystal.core._authenticated_request", return_value=io.BytesIO(b'{"owner_locator":"invalid"}')):
            with self.assertRaisesRegex(RuntimeError, "invalid owner locator"):
                fetch_owner_locator(auth_token="synthetic-test-token")

    def test_pull_binds_requested_id_and_client_context_even_without_unseal(self):
        expected = self.client.seal("one")
        other = self.client.seal("two")
        with patch("whitemagic_crystal.client.pull_crystal", return_value=other):
            with self.assertRaisesRegex(CrystalVerificationError, "different crystal ID"):
                self.client.pull(expected["crystal_id"], auto_unseal=False)
        wrong_context = copy.deepcopy(expected)
        wrong_context["tenant_hash"] = "sha256:" + "b" * 64
        with patch("whitemagic_crystal.client.pull_crystal", return_value=wrong_context):
            with self.assertRaises(CrystalContextError):
                self.client.pull(expected["crystal_id"], auto_unseal=False)
        with patch("whitemagic_crystal.client.pull_crystal", return_value=expected):
            _, plaintext = self.client.pull(expected["crystal_id"][7:])
            self.assertEqual(plaintext, b"one")

    def test_push_requires_matching_storage_confirmation(self):
        envelope = self.client.seal("synthetic")
        with patch("whitemagic_crystal.client.push_crystal", return_value={"stored": True, "crystal_id": envelope["crystal_id"]}) as push:
            self.assertTrue(self.client.push(envelope)["stored"])
            self.assertEqual(push.call_args.kwargs["api_url"], "https://api.whitemagic.dev")
        for response in ({"stored": False}, {"stored": True, "crystal_id": "sha256:" + "0" * 64}, {}):
            with self.subTest(response=response), patch("whitemagic_crystal.client.push_crystal", return_value=response):
                with self.assertRaises(CrystalVerificationError):
                    self.client.push(envelope)

    def test_cross_context_unseal_is_refused_even_with_same_key(self):
        local = CrystalClient("other", key=self.client.key)
        with self.assertRaises(CrystalContextError):
            local.unseal(self.client.seal("synthetic"))


class SessionPushContractTests(unittest.TestCase):
    def setUp(self):
        self.client = CrystalClient("demo", key=generate_key())
        self.manager = SessionMemoryManager("session", self.client, auto_push=True)

    def test_failed_push_blocks_chain_until_explicit_resolution(self):
        with patch.object(self.client, "push", side_effect=TimeoutError("synthetic timeout")):
            with self.assertRaises(TimeoutError):
                self.manager.append("user", "one")
        pending = self.manager.pending_envelope
        self.assertIsNotNone(pending)
        self.assertIsNone(self.manager.head_crystal_id)
        self.assertEqual(self.manager.get_history(), [])
        with self.assertRaisesRegex(RuntimeError, "unknown outcome"):
            self.manager.append("user", "two")
        with self.assertRaisesRegex(RuntimeError, "unknown outcome"):
            self.manager.clear()
        self.manager.resolve_pending(confirmed_stored=True)
        self.assertEqual(self.manager.head_crystal_id, pending["crystal_id"])
        self.assertEqual(self.manager.get_history()[0]["content"], "one")
        self.assertIsNone(self.manager.pending_envelope)

    def test_confirmed_absence_leaves_local_head_unchanged(self):
        with patch.object(self.client, "push", side_effect=TimeoutError("synthetic timeout")):
            with self.assertRaises(TimeoutError):
                self.manager.commit_checkpoint("checkpoint")
        with self.assertRaises(ValueError):
            self.manager.resolve_pending(confirmed_stored="yes")
        self.manager.resolve_pending(confirmed_stored=False)
        self.assertIsNone(self.manager.head_crystal_id)
        self.assertEqual(self.manager.get_history(), [])

    def test_manager_state_is_not_restored_by_a_new_instance(self):
        self.manager.auto_push = False
        self.manager.append("user", "one")
        fresh = SessionMemoryManager("session", self.client)
        self.assertEqual(fresh.get_history(), [])
        self.assertIsNone(fresh.pending_envelope)
        self.assertIsNone(fresh.head_crystal_id)

    def test_auto_push_must_be_a_boolean(self):
        with self.assertRaisesRegex(ValueError, "auto_push"):
            SessionMemoryManager("session", self.client, auto_push="false")


if __name__ == "__main__":
    unittest.main()
