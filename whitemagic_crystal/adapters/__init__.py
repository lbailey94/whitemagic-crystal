"""Framework adapters for whitemagic-crystal."""

from .generic import SessionMemoryManager

__all__ = ["SessionMemoryManager"]

try:
    from .langchain import CrystalChatMessageHistory
    __all__.append("CrystalChatMessageHistory")
except ImportError:
    pass
