# src/mitre_expert/chat/__init__.py
"""Chat module for conversational MITRE assistant."""

from .session import ChatSession, ChatMessage, get_or_create_session
from .coreference import resolve_coreferences

__all__ = [
    "ChatSession",
    "ChatMessage", 
    "get_or_create_session",
    "resolve_coreferences",
]
