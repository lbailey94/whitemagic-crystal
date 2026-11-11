"""Universal Session Memory Manager for AI Agents.

Compatible with any Python agent framework (CrewAI, AutoGen, OpenAI Swarm, custom agents).
"""

from __future__ import annotations

import copy
import os
import time
from typing import Any

from ..client import CrystalClient
from .journal import SessionJournal


class SessionMemoryManager:
    """Manages an authenticated, encrypted memory crystal chain for an AI agent session."""

    def __init__(
        self,
        session_id: str,
        client: CrystalClient,
        auto_push: bool = False,
        *,
        state_path: str | os.PathLike[str] | None = None,
    ):
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a nonempty string")
        if type(auto_push) is not bool:
            raise ValueError("auto_push must be a boolean")
        self.session_id = session_id
        self.client = client
        self.auto_push = auto_push
        self.head_crystal_id: str | None = None
        self._local_history: list[dict[str, Any]] = []
        self._pending_push: tuple[dict[str, Any], dict[str, Any] | None] | None = None
        self._journal = SessionJournal(state_path, client, session_id) if state_path is not None else None
        self._revision = 0
        if self._journal is not None:
            self._revision, state = self._journal.load()
            if state is None:
                self._set_state(None, [], None)
            else:
                self._restore_state(state)

    def _restore_state(self, state: dict[str, Any]) -> None:
        head, history, pending = state.get("head"), state.get("history"), state.get("pending")
        if (head is not None and not isinstance(head, str)) or not isinstance(history, list):
            raise ValueError("invalid encrypted session state")
        if any(not isinstance(turn, dict) or turn.get("session_id") != self.session_id for turn in history):
            raise ValueError("invalid session history")
        restored_pending = None
        if pending is not None:
            if not isinstance(pending, dict) or set(pending) != {"envelope", "payload"}:
                raise ValueError("invalid pending push")
            envelope, payload = pending["envelope"], pending["payload"]
            self.client._check_context(envelope)
            if envelope.get("parent_crystal_id") != head:
                raise ValueError("pending push is not an extension of the saved head")
            if payload is not None and (not isinstance(payload, dict) or payload.get("session_id") != self.session_id):
                raise ValueError("invalid pending payload")
            restored_pending = (envelope, payload)
        self.head_crystal_id, self._local_history, self._pending_push = head, history, restored_pending

    def _set_state(self, head, history, pending) -> None:
        if self._journal is not None:
            state = {
                "head": head,
                "history": history,
                "pending": {"envelope": pending[0], "payload": pending[1]} if pending is not None else None,
            }
            self._revision = self._journal.save(state, revision=self._revision)
        self.head_crystal_id = head
        self._local_history = copy.deepcopy(history)
        self._pending_push = copy.deepcopy(pending)

    @property
    def pending_envelope(self) -> dict[str, Any] | None:
        """Return the exact envelope whose remote outcome needs reconciliation."""
        return copy.deepcopy(self._pending_push[0]) if self._pending_push else None

    def _commit(self, envelope: dict[str, Any], payload: dict[str, Any] | None) -> None:
        if self._pending_push is not None:
            raise RuntimeError("a previous push has an unknown outcome; reconcile it first")
        if self.auto_push:
            # A lost response can follow a successful remote write. Preserve the
            # exact envelope and block new chain entries until reconciliation.
            self._set_state(self.head_crystal_id, self._local_history, (envelope, payload))
            self.client.push(envelope)
        history = self._local_history + ([payload] if payload is not None else [])
        self._set_state(envelope["crystal_id"], history, None)

    def resolve_pending(self, *, confirmed_stored: bool) -> None:
        """Resolve an uncertain push only after checking the remote outcome.

        ``False`` must only be used when the caller has established that the
        envelope was not stored. No network request is made by this method.
        """
        if type(confirmed_stored) is not bool:
            raise ValueError("confirmed_stored must be a boolean")
        if self._pending_push is None:
            raise RuntimeError("there is no pending push to reconcile")
        envelope, payload = self._pending_push
        head = envelope["crystal_id"] if confirmed_stored else self.head_crystal_id
        history = self._local_history + ([payload] if confirmed_stored and payload is not None else [])
        self._set_state(head, history, None)

    def append(
        self,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append a message/turn as an encrypted crystal linked to the session chain."""
        payload = {
            "session_id": self.session_id,
            "role": role,
            "content": content,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        envelope = self.client.seal(
            plaintext=payload,
            parent_id=self.head_crystal_id,
            tags=[f"session:{self.session_id}", f"role:{role}"],
        )
        self._commit(envelope, payload)

        return envelope

    def get_history(self) -> list[dict[str, Any]]:
        """Return the unsealed message history for the active session."""
        return copy.deepcopy(self._local_history)

    def format_context_prompt(self, max_turns: int = 10) -> str:
        """Format recent history into a standard conversational context block."""
        recent = self._local_history[-max_turns:]
        lines = []
        for turn in recent:
            role = turn.get("role", "user").capitalize()
            content = turn.get("content", "")
            lines.append(f"{role}: {content}")
        return "\n".join(lines)

    def commit_checkpoint(self, summary: str) -> dict[str, Any]:
        """Create a summary checkpoint crystal committing to the session state."""
        checkpoint_payload = {
            "session_id": self.session_id,
            "role": "system",
            "type": "checkpoint",
            "summary": summary,
            "head_crystal_id": self.head_crystal_id,
            "turn_count": len(self._local_history),
            "timestamp": time.time(),
        }
        envelope = self.client.seal(
            plaintext=checkpoint_payload,
            parent_id=self.head_crystal_id,
            tags=[f"session:{self.session_id}", "type:checkpoint"],
        )
        self._commit(envelope, None)
        return envelope

    def clear(self) -> None:
        """Reset local session state, including its journal; no remote deletion."""
        if self._pending_push is not None:
            raise RuntimeError("a previous push has an unknown outcome; reconcile it first")
        self._set_state(None, [], None)
