"""LangChain memory adapter for whitemagic-crystal."""

from __future__ import annotations

from typing import Any

from ..client import CrystalClient
from .generic import SessionMemoryManager

try:
    from langchain_core.chat_history import BaseChatMessageHistory
    from langchain_core.messages import (
        AIMessage,
        BaseMessage,
        ChatMessage,
        FunctionMessage,
        HumanMessage,
        SystemMessage,
        ToolMessage,
    )
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseChatMessageHistory = object  # type: ignore
    BaseMessage = object  # type: ignore


class CrystalChatMessageHistory(BaseChatMessageHistory):
    """LangChain BaseChatMessageHistory backed by authenticated encrypted memory crystals.

    Plaintext messages are encrypted locally before being stored or synchronized.
    """

    def __init__(
        self,
        session_id: str,
        client: CrystalClient,
        auto_push: bool = False,
    ):
        self.session_id = session_id
        self.client = client
        self.manager = SessionMemoryManager(
            session_id=session_id,
            client=client,
            auto_push=auto_push,
        )

    @property
    def messages(self) -> list[Any]:
        """Reconstruct messages held by this manager instance; no remote reload is performed."""
        history = self.manager.get_history()
        if not HAS_LANGCHAIN:
            return history

        result = []
        for turn in history:
            role = turn.get("role", "user")
            content = turn.get("content", "")
            if role == "human" or role == "user":
                result.append(HumanMessage(content=content))
            elif role == "ai" or role == "assistant":
                result.append(AIMessage(content=content))
            elif role == "system":
                result.append(SystemMessage(content=content))
            else:
                result.append(ChatMessage(role=role, content=content))
        return result

    def add_message(self, message: Any) -> None:
        """Add a message to the encrypted crystal chain."""
        if HAS_LANGCHAIN and isinstance(message, BaseMessage):
            role = getattr(message, "type", "user")
            content = getattr(message, "content", str(message))
        elif isinstance(message, dict):
            role = message.get("role", "user")
            content = message.get("content", "")
        else:
            role = "user"
            content = str(message)

        self.manager.append(role=role, content=content)

    def add_user_message(self, message: str) -> None:
        self.manager.append(role="user", content=message)

    def add_ai_message(self, message: str) -> None:
        self.manager.append(role="assistant", content=message)

    def clear(self) -> None:
        """Clear local session state only; no remote crystals are deleted."""
        self.manager.clear()
