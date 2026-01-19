# src/mitre_expert/chat/session.py
"""
Conversation session management for the MITRE chatbot.

Provides:
- ChatMessage: Individual message in a conversation
- ChatSession: Full conversation state with context tracking
- Session store: In-memory store (swap for Redis/DB in production)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class ChatMessage:
    """A single message in a conversation."""
    
    role: str  # "user" | "assistant" | "system"
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ChatSession:
    """
    Conversation session with memory and context tracking.
    
    Tracks:
    - Full message history
    - Current technique being discussed (for coreference resolution)
    - All mentioned techniques (for context)
    - User's environment settings (available logs, platform)
    """
    
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    messages: List[ChatMessage] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Conversation state for coreference resolution
    current_technique_id: Optional[str] = None
    current_technique_name: Optional[str] = None
    current_tactics: List[str] = field(default_factory=list)
    mentioned_techniques: List[str] = field(default_factory=list)
    
    # User environment context (persists across turns)
    user_environment: Dict[str, Any] = field(default_factory=dict)
    
    def add_message(
        self,
        role: str,
        content: str,
        **metadata: Any,
    ) -> ChatMessage:
        """Add a message to the conversation history."""
        msg = ChatMessage(role=role, content=content, metadata=metadata)
        self.messages.append(msg)
        self.updated_at = datetime.utcnow()
        return msg
    
    def get_history_for_llm(self, max_turns: int = 10) -> List[Dict[str, str]]:
        """
        Format recent history for LLM context window.
        
        Returns list of {"role": ..., "content": ...} dicts
        suitable for chat-style LLM APIs.
        """
        # Get recent messages (user + assistant pairs)
        recent = self.messages[-max_turns * 2:]
        return [{"role": m.role, "content": m.content} for m in recent]
    
    def get_context_summary(self) -> str:
        """
        Generate a brief context summary for the LLM.
        
        Useful for injecting into system prompts to remind
        the LLM about conversation state.
        """
        parts: List[str] = []
        
        if self.current_technique_id:
            name_part = f" ({self.current_technique_name})" if self.current_technique_name else ""
            parts.append(f"Currently discussing: {self.current_technique_id}{name_part}")
        
        if self.current_tactics:
            parts.append(f"Tactics in scope: {', '.join(self.current_tactics)}")
        
        if len(self.mentioned_techniques) > 1:
            others = [t for t in self.mentioned_techniques if t != self.current_technique_id]
            if others:
                parts.append(f"Previously mentioned: {', '.join(others[-5:])}")
        
        env = self.user_environment
        if env.get("available_logs"):
            parts.append(f"User's log sources: {', '.join(env['available_logs'][:5])}")
        if env.get("platform"):
            parts.append(f"Platform: {env['platform']}")
        
        return "\n".join(parts) if parts else "No prior context."
    
    def update_context(
        self,
        technique_id: Optional[str] = None,
        technique_name: Optional[str] = None,
        tactics: Optional[List[str]] = None,
    ) -> None:
        """
        Update conversation context after a response.
        
        Called after each assistant turn to track what
        entities were discussed.
        """
        if technique_id:
            self.current_technique_id = technique_id
            if technique_id not in self.mentioned_techniques:
                self.mentioned_techniques.append(technique_id)
        
        if technique_name:
            self.current_technique_name = technique_name
        
        if tactics:
            self.current_tactics = tactics
        
        self.updated_at = datetime.utcnow()
    
    def set_environment(
        self,
        available_logs: Optional[List[str]] = None,
        platform: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Update user's environment settings."""
        if available_logs is not None:
            self.user_environment["available_logs"] = available_logs
        if platform is not None:
            self.user_environment["platform"] = platform
        for k, v in kwargs.items():
            self.user_environment[k] = v
        self.updated_at = datetime.utcnow()
    
    def clear_context(self) -> None:
        """Reset conversation context (but keep history)."""
        self.current_technique_id = None
        self.current_technique_name = None
        self.current_tactics = []
        # Keep mentioned_techniques as historical reference
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize session for API responses or storage."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "message_count": len(self.messages),
            "messages": [m.to_dict() for m in self.messages],
            "context": {
                "current_technique_id": self.current_technique_id,
                "current_technique_name": self.current_technique_name,
                "current_tactics": self.current_tactics,
                "mentioned_techniques": self.mentioned_techniques,
            },
            "user_environment": self.user_environment,
        }


# ---------------------------------------------------------------------------
# Session Store (In-Memory)
# For production, replace with Redis, PostgreSQL, or another persistent store
# ---------------------------------------------------------------------------

_sessions: Dict[str, ChatSession] = {}


def get_or_create_session(session_id: Optional[str] = None) -> ChatSession:
    """
    Get an existing session or create a new one.
    
    Args:
        session_id: Optional session ID. If provided and exists, returns that session.
                   If not provided, creates a new session.
    
    Returns:
        ChatSession instance
    """
    if session_id and session_id in _sessions:
        return _sessions[session_id]
    
    # Create new session
    new_id = session_id or str(uuid.uuid4())
    session = ChatSession(session_id=new_id)
    _sessions[new_id] = session
    return session


def get_session(session_id: str) -> Optional[ChatSession]:
    """Get a session by ID, or None if not found."""
    return _sessions.get(session_id)


def delete_session(session_id: str) -> bool:
    """Delete a session. Returns True if deleted, False if not found."""
    if session_id in _sessions:
        del _sessions[session_id]
        return True
    return False


def list_sessions() -> List[Dict[str, Any]]:
    """List all active sessions (summary info only)."""
    return [
        {
            "session_id": s.session_id,
            "created_at": s.created_at.isoformat(),
            "updated_at": s.updated_at.isoformat(),
            "message_count": len(s.messages),
            "current_technique": s.current_technique_id,
        }
        for s in _sessions.values()
    ]


def cleanup_old_sessions(max_age_hours: int = 24) -> int:
    """
    Remove sessions older than max_age_hours.
    
    Returns count of deleted sessions.
    """
    from datetime import timedelta
    
    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
    to_delete = [
        sid for sid, session in _sessions.items()
        if session.updated_at < cutoff
    ]
    
    for sid in to_delete:
        del _sessions[sid]
    
    return len(to_delete)
