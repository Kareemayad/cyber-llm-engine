# src/mitre_expert/api/routers/chat.py
"""
Chat endpoint with conversation memory for the MITRE assistant.

Provides:
- POST /chat - Send a message and get a response (with session continuity)
- GET /chat/{session_id}/history - Get conversation history
- DELETE /chat/{session_id} - Clear a session
- GET /chat/sessions - List active sessions (admin)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from mitre_expert.chat.session import (
    get_or_create_session,
    get_session,
    delete_session,
    list_sessions,
    cleanup_old_sessions,
)
from mitre_expert.chat.coreference import (
    resolve_coreferences,
    extract_technique_from_response,
    build_context_injection,
)

# Import the existing query endpoint logic
from mitre_expert.api.routers.router import query_endpoint, QueryRequest

router = APIRouter(prefix="/chat", tags=["chat"])


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    """Request model for chat endpoint."""
    
    message: str = Field(..., description="User message", min_length=1)
    session_id: Optional[str] = Field(
        None,
        description="Session ID for conversation continuity. If not provided, creates new session.",
    )
    
    # Dataset and retrieval options
    dataset: str = Field(
        "mitre",
        description="Dataset to use: 'mitre' | 'd3fend' | 'all'",
    )
    
    # Environment context (optional, persists in session)
    available_logs: Optional[List[str]] = Field(
        None,
        description="Available log sources in your environment (e.g., ['Sysmon', 'Windows Security'])",
    )
    platform: Optional[str] = Field(
        None,
        description="Platform filter (e.g., 'Windows', 'Linux', 'macOS')",
    )
    
    # Advanced options
    topk: int = Field(8, ge=1, le=32, description="Number of chunks to retrieve")
    include_context_debug: bool = Field(
        False,
        description="Include debug info about coreference resolution",
    )


class ChatResponse(BaseModel):
    """Response model for chat endpoint."""
    
    session_id: str = Field(..., description="Session ID for follow-up messages")
    message: str = Field(..., description="Original user message")
    answer: str = Field(..., description="Assistant's response")
    
    # Context tracking (useful for UI)
    current_technique: Optional[str] = Field(
        None,
        description="Currently focused technique ID",
    )
    current_technique_name: Optional[str] = Field(
        None,
        description="Currently focused technique name",
    )
    mentioned_techniques: List[str] = Field(
        default_factory=list,
        description="All techniques mentioned in this conversation",
    )
    tactics: List[str] = Field(
        default_factory=list,
        description="Tactics from the response",
    )
    
    # Routing info
    route_kind: str = Field("", description="How the query was routed")
    
    # Debug info (optional)
    resolved_query: Optional[str] = Field(
        None,
        description="Query after coreference resolution (if different from original)",
    )
    context_injection: Optional[str] = Field(
        None,
        description="Context injected into the query (debug)",
    )


class SessionHistoryResponse(BaseModel):
    """Response model for session history endpoint."""
    
    session_id: str
    created_at: str
    updated_at: str
    message_count: int
    messages: List[Dict[str, Any]]
    context: Dict[str, Any]
    user_environment: Dict[str, Any]


class SessionListResponse(BaseModel):
    """Response model for session list endpoint."""
    
    sessions: List[Dict[str, Any]]
    total_count: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=ChatResponse)
async def chat_endpoint(payload: ChatRequest) -> ChatResponse:
    """
    Send a message to the MITRE assistant with conversation memory.
    
    This endpoint maintains session state across turns:
    - Resolves pronouns like "it", "this technique" to previously mentioned techniques
    - Tracks user's environment (available logs, platform) across the session
    - Provides conversation continuity
    
    Example conversation:
    ```
    User: What is T1059?
    Bot:  T1059 is Command and Scripting Interpreter...
    
    User: How do I detect it?
          [automatically resolved to: "How do I detect T1059?"]
    Bot:  To detect T1059, monitor for process creation events...
    
    User: What about mitigations?
          [automatically resolved to: "What about T1059 mitigations?"]
    Bot:  Key mitigations for T1059 include...
    ```
    """
    # Get or create session
    session = get_or_create_session(payload.session_id)
    
    # Update session with user environment if provided
    if payload.available_logs is not None:
        session.set_environment(available_logs=payload.available_logs)
    if payload.platform is not None:
        session.set_environment(platform=payload.platform)
    
    # Resolve coreferences ("it" -> "T1059")
    resolved_query = resolve_coreferences(payload.message, session)
    
    # Build optional context injection for the LLM
    context_injection = build_context_injection(session)
    
    # Record user message in history
    session.add_message(
        role="user",
        content=payload.message,
        resolved_query=resolved_query if resolved_query != payload.message else None,
    )
    
    # Build query request with session context
    query_req = QueryRequest(
        query=resolved_query,
        dataset=payload.dataset,
        mode="search",
        technique_id=None,  # Let the system detect from resolved query
        available_logs=payload.available_logs or session.user_environment.get("available_logs"),
        platform=payload.platform or session.user_environment.get("platform"),
        topk=payload.topk,
        include_raw_sections=False,
    )
    
    # Call existing query endpoint
    try:
        result = await query_endpoint(query_req)
    except Exception as e:
        # Record error and re-raise
        session.add_message(
            role="assistant",
            content=f"Error processing request: {str(e)}",
            error=True,
        )
        raise HTTPException(status_code=500, detail=str(e))
    
    # Clean up the answer - remove composer headers for pure docqa/d3fend routes
    answer = result.answer
    if result.route_kind in ("docqa", "d3fend_docqa"):
        # Remove various forms of the "Additional Context" header
        for prefix in [
            "## Additional Context\n",
            "## Additional Context\r\n",
            "## Additional Context\n\n",
            "## Additional Context ",
        ]:
            if answer.startswith(prefix):
                answer = answer[len(prefix):].strip()
                break
    
    # Extract technique from response and update session context
    technique_id = None
    technique_name = None
    
    # Try to get from structured response first
    if result.techniques:
        for tech in result.techniques:
            if isinstance(tech, dict):
                technique_id = tech.get("id") or tech.get("technique_id")
                technique_name = tech.get("name") or tech.get("technique_name")
                if technique_id:
                    break
    
    # Fall back to extraction from answer text
    if not technique_id:
        technique_id = extract_technique_from_response(result.answer, result.techniques)
    
    # Update session context
    session.update_context(
        technique_id=technique_id,
        technique_name=technique_name,
        tactics=result.tactics,
    )
    
    # Record assistant response
    session.add_message(
        role="assistant",
        content=result.answer,
        technique_id=technique_id,
        route_kind=result.route_kind,
    )
    
    return ChatResponse(
        session_id=session.session_id,
        message=payload.message,
        answer=answer,  # Use cleaned answer
        current_technique=session.current_technique_id,
        current_technique_name=session.current_technique_name,
        mentioned_techniques=session.mentioned_techniques,
        tactics=result.tactics,
        route_kind=result.route_kind,
        resolved_query=resolved_query if (
            payload.include_context_debug and resolved_query != payload.message
        ) else None,
        context_injection=context_injection if payload.include_context_debug else None,
    )


@router.get("/{session_id}/history", response_model=SessionHistoryResponse)
async def get_chat_history(session_id: str) -> SessionHistoryResponse:
    """
    Retrieve conversation history for a session.
    
    Returns full message history and current context state.
    """
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    
    data = session.to_dict()
    return SessionHistoryResponse(
        session_id=data["session_id"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        message_count=data["message_count"],
        messages=data["messages"],
        context=data["context"],
        user_environment=data["user_environment"],
    )


@router.delete("/{session_id}")
async def clear_chat_session(session_id: str) -> Dict[str, Any]:
    """
    Delete a conversation session.
    
    This clears all history and context for the session.
    """
    if delete_session(session_id):
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail=f"Session {session_id} not found")


@router.post("/{session_id}/reset-context")
async def reset_session_context(session_id: str) -> Dict[str, Any]:
    """
    Reset conversation context without clearing history.
    
    Useful when the user wants to start discussing a new topic
    without losing the conversation history.
    """
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    
    session.clear_context()
    return {
        "status": "context_reset",
        "session_id": session_id,
        "message": "Context cleared. History preserved. You can start a new topic.",
    }


@router.get("/sessions", response_model=SessionListResponse)
async def list_chat_sessions() -> SessionListResponse:
    """
    List all active chat sessions.
    
    Admin/debug endpoint to see active sessions.
    """
    sessions = list_sessions()
    return SessionListResponse(
        sessions=sessions,
        total_count=len(sessions),
    )


@router.post("/sessions/cleanup")
async def cleanup_sessions(max_age_hours: int = 24) -> Dict[str, Any]:
    """
    Clean up old inactive sessions.
    
    Removes sessions that haven't been updated in the specified time.
    """
    if max_age_hours < 1:
        raise HTTPException(status_code=400, detail="max_age_hours must be at least 1")
    
    deleted_count = cleanup_old_sessions(max_age_hours)
    return {
        "status": "cleanup_complete",
        "deleted_sessions": deleted_count,
        "max_age_hours": max_age_hours,
    }