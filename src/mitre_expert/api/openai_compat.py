# src/mitre_expert/api/openai_compat.py
"""
OpenAI-compatible API wrapper for Open WebUI integration.

This creates /v1/chat/completions endpoint that Open WebUI can connect to.
It translates OpenAI format to our MITRE chat format and back.

Usage:
    1. Start your server: uvicorn mitre_expert.api.main:app --port 8000
    2. In Open WebUI, add a new OpenAI connection:
       - Base URL: http://localhost:8000/v1
       - API Key: any-string (we don't validate)
       - Model: mitre-expert
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import json

from mitre_expert.chat.session import get_or_create_session, ChatSession
from mitre_expert.chat.coreference import resolve_coreferences
from mitre_expert.api.routers.router import query_endpoint, QueryRequest

router = APIRouter(prefix="/v1", tags=["openai-compat"])


# ---------------------------------------------------------------------------
# OpenAI-compatible request/response models
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: str  # "system" | "user" | "assistant"
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = Field(default="mitre-expert")
    messages: List[ChatMessage]
    temperature: Optional[float] = Field(default=0.7)
    max_tokens: Optional[int] = Field(default=1024)
    stream: Optional[bool] = Field(default=False)
    
    # Custom fields for MITRE context (optional)
    available_logs: Optional[List[str]] = None
    platform: Optional[str] = None


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str = "stop"


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: Usage


class ModelInfo(BaseModel):
    id: str
    object: str = "model"
    created: int = 1700000000
    owned_by: str = "mitre-expert"


class ModelList(BaseModel):
    object: str = "list"
    data: List[ModelInfo]


# ---------------------------------------------------------------------------
# Session management for OpenAI format
# ---------------------------------------------------------------------------

def _extract_session_id_from_messages(messages: List[ChatMessage]) -> Optional[str]:
    """
    Try to extract a session ID from the conversation.
    We use a convention: if the system message contains [session:xxx], use that.
    """
    for msg in messages:
        if msg.role == "system" and "[session:" in msg.content:
            # Extract session ID from [session:xxx]
            start = msg.content.find("[session:") + 9
            end = msg.content.find("]", start)
            if end > start:
                return msg.content[start:end]
    return None


def _get_last_user_message(messages: List[ChatMessage]) -> str:
    """Get the last user message from the conversation."""
    for msg in reversed(messages):
        if msg.role == "user":
            return msg.content
    return ""


def _build_context_from_history(messages: List[ChatMessage], session: ChatSession) -> None:
    """
    Replay message history to build up session context.
    This helps with coreference resolution.
    """
    import re
    TECHID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
    
    for msg in messages:
        if msg.role == "assistant":
            # Extract technique IDs from assistant responses
            matches = TECHID_RE.findall(msg.content)
            if matches:
                # Update context with the last mentioned technique
                session.update_context(technique_id=matches[-1].upper())


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/models")
async def list_models() -> ModelList:
    """List available models (OpenAI-compatible)."""
    return ModelList(
        data=[
            ModelInfo(id="mitre-expert", owned_by="mitre-expert"),
            ModelInfo(id="mitre-expert-detect", owned_by="mitre-expert"),
            ModelInfo(id="mitre-expert-mapper", owned_by="mitre-expert"),
        ]
    )


@router.get("/models/{model_id}")
async def get_model(model_id: str) -> ModelInfo:
    """Get model info (OpenAI-compatible)."""
    return ModelInfo(id=model_id, owned_by="mitre-expert")


@router.post("/chat/completions")
async def chat_completions(request: ChatCompletionRequest):
    """
    OpenAI-compatible chat completions endpoint.
    
    This is the main endpoint that Open WebUI will call.
    """
    # Get or create session
    session_id = _extract_session_id_from_messages(request.messages)
    session = get_or_create_session(session_id)
    
    # Build context from message history
    _build_context_from_history(request.messages, session)
    
    # Get the user's message
    user_message = _get_last_user_message(request.messages)
    if not user_message:
        raise HTTPException(status_code=400, detail="No user message found")
    
    # Resolve coreferences
    resolved_query = resolve_coreferences(user_message, session)
    
    # Update session environment if provided
    if request.available_logs:
        session.set_environment(available_logs=request.available_logs)
    if request.platform:
        session.set_environment(platform=request.platform)
    
    # Build query request
    query_req = QueryRequest(
        query=resolved_query,
        dataset="mitre",
        mode="search",
        available_logs=request.available_logs or session.user_environment.get("available_logs"),
        platform=request.platform or session.user_environment.get("platform"),
        topk=8,
        include_raw_sections=False,
    )
    
    # Call the MITRE query endpoint
    try:
        result = await query_endpoint(query_req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    # Clean up answer
    answer = result.answer
    if result.route_kind in ("docqa", "d3fend_docqa"):
        for prefix in ["## Additional Context\n", "## Additional Context\r\n", "## Additional Context "]:
            if answer.startswith(prefix):
                answer = answer[len(prefix):].strip()
                break
    
    # Update session context from response
    if result.techniques:
        for tech in result.techniques:
            if isinstance(tech, dict):
                tid = tech.get("id") or tech.get("technique_id")
                tname = tech.get("name") or tech.get("technique_name")
                if tid:
                    session.update_context(technique_id=tid, technique_name=tname)
                    break
    
    # Record in session
    session.add_message("user", user_message)
    session.add_message("assistant", answer)
    
    # Build response
    response_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
    
    if request.stream:
        # Streaming response
        return StreamingResponse(
            _stream_response(response_id, request.model, answer),
            media_type="text/event-stream",
        )
    
    # Non-streaming response
    return ChatCompletionResponse(
        id=response_id,
        created=int(time.time()),
        model=request.model,
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content=answer),
                finish_reason="stop",
            )
        ],
        usage=Usage(
            prompt_tokens=len(user_message.split()),
            completion_tokens=len(answer.split()),
            total_tokens=len(user_message.split()) + len(answer.split()),
        ),
    )


async def _stream_response(response_id: str, model: str, content: str) -> AsyncIterator[str]:
    """Generate streaming response chunks."""
    # Split content into chunks for streaming effect
    words = content.split()
    chunk_size = 5  # Words per chunk
    
    for i in range(0, len(words), chunk_size):
        chunk_words = words[i:i + chunk_size]
        chunk_text = " ".join(chunk_words)
        if i > 0:
            chunk_text = " " + chunk_text
        
        chunk_data = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": chunk_text},
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(chunk_data)}\n\n"
    
    # Send final chunk
    final_chunk = {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }
        ],
    }
    yield f"data: {json.dumps(final_chunk)}\n\n"
    yield "data: [DONE]\n\n"