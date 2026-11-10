"""Universal Session Memory Manager for AI Agents.

Compatible with any Python agent framework (CrewAI, AutoGen, OpenAI Swarm, custom agents).
"""

from __future__ import annotations

import copy
import time
from typing import Any

from ..client import CrystalClient


class SessionMemoryManager:
    """Manages an authenticated, encrypted memory crystal chain for an AI agent session."""

    def __init__(
        self,
        session_id: str,
        client: CrystalClient,
        auto_push: bool = False,
    ):
        if type(auto_push) is not bool:
            raise ValueError("auto_push must be a boolean")
        self.session_id = session_id
        self.client = client
        self.auto_push = auto_push
        self.head_crystal_id: str | None = None
        self._local_history: list[dict[str, Any]] = []
        self._pending_push: tuple[dict[str, Any], dict[str, Any] | None] | None = None

    @property
    def pending_envelope(self) -> dict[str, Any] | None:
        """Return a copy of a push with an unknown outcome in this process only."""
        return copy.deepcopy(self._pending_push[0]) if self._pending_push else None

    def _commit(self, envelope: dict[str, Any], payload: dict[str, Any] | None) -> None:
        if self._pending_push is not None:
            raise RuntimeError("a previous push has an unknown outcome; reconcile it first")
        if self.auto_push:
            # A lost response can follow a successful remote write. Preserve the
            # exact envelope and block new chain entries until reconciliation.
            self._pending_push = (copy.deepcopy(envelope), copy.deepcopy(payload))
            self.client.push(envelope)
            self._pending_push = None
        self.head_crystal_id = envelope["crystal_id"]
        if payload is not None:
            self._local_history.append(payload)

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
        if confirmed_stored:
            self.head_crystal_id = envelope["crystal_id"]
            if payload is not None:
                self._local_history.append(payload)
        self._pending_push = None

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
        return list(self._local_history)

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
        """Clear local process state only; this does not delete remote data."""
        if self._pending_push is not None:
            raise RuntimeError("a previous push has an unknown outcome; reconcile it first")
        self._local_history.clear()
        self.head_crystal_id = None
