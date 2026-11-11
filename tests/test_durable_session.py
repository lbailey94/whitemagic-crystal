"""Restart and uncertain-write behavior using synthetic state and no network."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from whitemagic_crystal import CrystalClient, generate_key
from whitemagic_crystal.adapters.generic import SessionMemoryManager
from whitemagic_crystal.adapters.langchain import CrystalChatMessageHistory


class DurableSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "session.sqlite3"
        self.client = CrystalClient("test-tenant", key=generate_key())

    def manager(self, **kwargs):
        return SessionMemoryManager("test-session", self.client, state_path=self.path, **kwargs)

    def test_history_head_and_checkpoint_survive_reopen(self):
        first = self.manager()
        message = first.append("user", "retain this decision")
        checkpoint = first.commit_checkpoint("next step")
        fresh = self.manager()
        self.assertEqual(fresh.head_crystal_id, checkpoint["crystal_id"])
        self.assertEqual(fresh.get_history(), first.get_history())
        next_message = fresh.append("assistant", "continue")
        self.assertEqual(next_message["parent_crystal_id"], checkpoint["crystal_id"])
        self.assertEqual(checkpoint["parent_crystal_id"], message["crystal_id"])
        fresh.clear()
        cleared = self.manager()
        self.assertEqual(cleared.get_history(), [])
        self.assertIsNone(cleared.head_crystal_id)

    def test_timeout_persists_exact_pending_and_blocks_restart(self):
        first = self.manager(auto_push=True)
        with patch.object(self.client, "push", side_effect=TimeoutError("synthetic timeout")):
            with self.assertRaises(TimeoutError):
                first.append("user", "possibly delivered")
        fresh = self.manager(auto_push=True)
        self.assertEqual(fresh.pending_envelope, first.pending_envelope)
        with self.assertRaisesRegex(RuntimeError, "unknown outcome"):
            fresh.append("user", "must wait")
        with self.assertRaisesRegex(RuntimeError, "unknown outcome"):
            fresh.clear()
        fresh.resolve_pending(confirmed_stored=True)
        again = self.manager()
        self.assertIsNone(again.pending_envelope)
        self.assertEqual(again.head_crystal_id, first.pending_envelope["crystal_id"])
        self.assertEqual(again.get_history()[0]["content"], "possibly delivered")

    def test_confirmed_absence_and_checkpoint_reconcile_after_restart(self):
        first = self.manager()
        first.append("user", "already committed")
        original = first.head_crystal_id
        first.auto_push = True
        with patch.object(self.client, "push", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                first.commit_checkpoint("uncertain checkpoint")
        fresh = self.manager()
        fresh.resolve_pending(confirmed_stored=False)
        again = self.manager()
        self.assertEqual(again.head_crystal_id, original)
        self.assertEqual(len(again.get_history()), 1)

    def test_successful_push_is_committed_after_reopen(self):
        first = self.manager(auto_push=True)
        with patch.object(self.client, "push") as push:
            message = first.append("user", "confirmed")
        push.assert_called_once_with(message)
        fresh = self.manager()
        self.assertEqual(fresh.head_crystal_id, message["crystal_id"])
        self.assertIsNone(fresh.pending_envelope)

    def test_failure_before_pending_write_does_not_send(self):
        first = self.manager(auto_push=True)
        with patch.object(first._journal, "save", side_effect=OSError("disk full")), patch.object(self.client, "push") as push:
            with self.assertRaises(OSError):
                first.append("user", "cannot save")
        push.assert_not_called()
        self.assertIsNone(first.pending_envelope)
        self.assertEqual(self.manager().get_history(), [])

    def test_failure_after_remote_confirmation_retains_pending(self):
        first = self.manager(auto_push=True)
        save = first._journal.save
        def fail_final(state, *, revision):
            if state["pending"] is None:
                raise OSError("disk full after remote success")
            return save(state, revision=revision)
        with patch.object(first._journal, "save", side_effect=fail_final), patch.object(self.client, "push") as push:
            with self.assertRaises(OSError):
                first.append("user", "remote success")
        push.assert_called_once()
        fresh = self.manager()
        self.assertEqual(fresh.pending_envelope, first.pending_envelope)
        self.assertEqual(fresh.get_history(), [])
        fresh.resolve_pending(confirmed_stored=True)
        self.assertEqual(len(self.manager().get_history()), 1)

    def test_stale_manager_cannot_overwrite_or_send(self):
        first, stale = self.manager(), self.manager(auto_push=True)
        first.append("user", "winner")
        with patch.object(self.client, "push") as push:
            with self.assertRaisesRegex(RuntimeError, "another manager"):
                stale.append("user", "stale")
        push.assert_not_called()
        self.assertEqual(self.manager().get_history()[0]["content"], "winner")

    def test_state_is_encrypted_and_history_copies_cannot_mutate_it(self):
        first = self.manager()
        first.append("user", "private-test-message-9bc4", metadata={"private": "secret-marker"})
        edited = first.get_history()
        edited[0]["metadata"]["private"] = "changed"
        self.assertEqual(first.get_history()[0]["metadata"]["private"], "secret-marker")
        for path in self.path.parent.iterdir():
            self.assertNotIn(b"private-test-message-9bc4", path.read_bytes())
            self.assertNotIn(b"secret-marker", path.read_bytes())
            self.assertNotIn(self.client.key.hex().encode(), path.read_bytes())
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_other_session_tenant_origin_and_key_are_refused(self):
        self.manager().append("user", "bound state")
        with self.assertRaisesRegex(ValueError, "different session"):
            SessionMemoryManager("different", self.client, state_path=self.path)
        for client in (
            CrystalClient("different", key=self.client.key),
            CrystalClient("test-tenant", key=self.client.key, api_url="https://elsewhere.invalid"),
            CrystalClient("test-tenant", key=generate_key()),
        ):
            with self.subTest(context=client.tenant_id + client.api_url), self.assertRaises(ValueError):
                SessionMemoryManager("test-session", client, state_path=self.path)

    def test_tampered_ciphertext_is_refused(self):
        self.manager().append("user", "protected")
        with sqlite3.connect(self.path) as db:
            envelope = json.loads(db.execute("SELECT envelope FROM session_state").fetchone()[0])
            ciphertext = envelope["ciphertext"]
            envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
            db.execute("UPDATE session_state SET envelope=?", (json.dumps(envelope),))
        with self.assertRaises(ValueError):
            self.manager()

    @unittest.skipUnless(os.name == "posix", "POSIX private-directory checks")
    def test_public_directory_file_and_symlink_are_refused(self):
        self.path.parent.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.manager()
        self.path.parent.chmod(0o700)
        self.manager()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            self.manager()
        self.path.chmod(0o600)
        link = self.path.parent / "link.sqlite3"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, "regular file"):
            SessionMemoryManager("test-session", self.client, state_path=link)

    def test_adapter_accepts_durable_state(self):
        first = CrystalChatMessageHistory("test-session", self.client, state_path=self.path)
        first.add_user_message("retained")
        fresh = CrystalChatMessageHistory("test-session", self.client, state_path=self.path)
        self.assertEqual(fresh.manager.get_history()[0]["content"], "retained")

    def test_process_exit_inside_push_retains_write_ahead_state(self):
        # Key is synthetic and supplied only to this child process; it is not
        # printed, embedded in argv or persisted in the session database.
        script = """
import os
from whitemagic_crystal import CrystalClient
from whitemagic_crystal.adapters.generic import SessionMemoryManager
client = CrystalClient('test-tenant', key=bytes.fromhex(os.environ['TEST_SESSION_KEY']))
client.push = lambda envelope: os._exit(73)
manager = SessionMemoryManager('test-session', client, auto_push=True, state_path=os.environ['TEST_SESSION_PATH'])
manager.append('user', 'crash during push')
"""
        env = {**os.environ, "TEST_SESSION_KEY": self.client.key.hex(), "TEST_SESSION_PATH": str(self.path)}
        child = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 73, child.stderr.decode())
        fresh = self.manager()
        self.assertIn("crash during push", self.client.unseal_text(fresh.pending_envelope))
        fresh.resolve_pending(confirmed_stored=True)
        self.assertEqual(self.manager().get_history()[0]["content"], "crash during push")


if __name__ == "__main__":
    unittest.main()
