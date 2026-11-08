"""Universal Session Memory Manager for AI Agents.

Compatible with any Python agent framework (CrewAI, AutoGen, OpenAI Swarm, custom agents).
"""

from __future__ import annotations

import json
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
        self.session_id = session_id
        self.client = client
        self.auto_push = auto_push
        self.head_crystal_id: str | None = None
        self._local_history: list[dict[str, Any]] = []

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
        crystal_id = envelope["id"]
        self.head_crystal_id = crystal_id
        self._local_history.append(payload)

        if self.auto_push:
            self.client.push(envelope)

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
        self.head_crystal_id = envelope["id"]
        if self.auto_push:
            self.client.push(envelope)
        return envelope
