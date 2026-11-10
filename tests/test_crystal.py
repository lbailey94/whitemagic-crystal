"""Unit tests for whitemagic-crystal."""

import unittest
from whitemagic_crystal.client import CrystalClient
from whitemagic_crystal.core import (
    CrystalVerificationError,
    compute_crystal_id,
    compute_tenant_hash,
    generate_key,
    seal_crystal,
    unseal_crystal,
)
from whitemagic_crystal.adapters.generic import SessionMemoryManager
from whitemagic_crystal.adapters.langchain import CrystalChatMessageHistory


class TestWhitemagicCrystal(unittest.TestCase):
    def setUp(self):
        self.tenant_id = "test-agent-alpha"
        self.client = CrystalClient(tenant_id=self.tenant_id, key=generate_key())

    def test_keygen_aes_and_chacha(self):
        k_aes = generate_key("AES-256-GCM")
        self.assertEqual(len(k_aes), 32)
        k_chacha = generate_key("ChaCha20-Poly1305")
        self.assertEqual(len(k_chacha), 32)

    def test_seal_unseal_roundtrip_string(self):
        secret = "Sovereign intelligence requires client-side encrypted memory."
        envelope = self.client.seal(secret)
        self.assertIn("id", envelope)
        self.assertTrue(envelope["id"].startswith("sha256:"))
        self.assertEqual(envelope["tenant_hash"], self.client.tenant_hash)

        plaintext = self.client.unseal(envelope)
        self.assertEqual(plaintext.decode("utf-8"), secret)

    def test_seal_unseal_roundtrip_dict(self):
        payload = {"agent": "Antigravity", "goal": "Zero data loss", "count": 42}
        envelope = self.client.seal(payload)
        plaintext = self.client.unseal(envelope)
        import json
        decoded = json.loads(plaintext.decode("utf-8"))
        self.assertEqual(decoded, payload)

    def test_tamper_detection(self):
        import base64
        secret = "Secret memory payload"
        envelope = self.client.seal(secret)
        # Corrupt ciphertext bit
        raw_bytes = bytearray(base64.urlsafe_b64decode(envelope["ciphertext"]))
        raw_bytes[-1] ^= 0xFF
        envelope["ciphertext"] = base64.urlsafe_b64encode(raw_bytes).decode("ascii")

        with self.assertRaises((CrystalVerificationError, ValueError)):
            self.client.unseal(envelope)

    def test_lineage_chaining(self):
        c1 = self.client.seal("Turn 1: Observe state")
        c2 = self.client.seal("Turn 2: Execute action", parent_id=c1["id"])
        self.assertEqual(c2["parent_crystal_id"], c1["id"])

    def test_session_memory_manager(self):
        manager = SessionMemoryManager(session_id="sess-100", client=self.client)
        e1 = manager.append("user", "Hello agent")
        e2 = manager.append("assistant", "Hello human, memory is encrypted")
        self.assertEqual(manager.head_crystal_id, e2["id"])

        history = manager.get_history()
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["content"], "Hello agent")
        self.assertEqual(history[1]["content"], "Hello human, memory is encrypted")

        prompt = manager.format_context_prompt()
        self.assertIn("User: Hello agent", prompt)
        self.assertIn("Assistant: Hello human, memory is encrypted", prompt)

    def test_langchain_adapter_duck_typing(self):
        history = CrystalChatMessageHistory(session_id="sess-lc", client=self.client)
        history.add_user_message("Task starting")
        history.add_ai_message("Task running")
        msgs = history.messages
        self.assertEqual(len(msgs), 2)


if __name__ == "__main__":
    unittest.main()
