# src/mitre_expert/api/main.py
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from mitre_expert.api.routers import (
    mitre_docqa,
    mitre_mapper,
    mitre_detect,
    d3fend_docqa,
    router as query_router,
    chat,
)

# Optional: OpenAI-compatible endpoint for Open WebUI
try:
    from mitre_expert.api import openai_compat
    HAS_OPENAI_COMPAT = True
except ImportError:
    HAS_OPENAI_COMPAT = False

app = FastAPI(
    title="Cyber LLM Engine – MITRE Expert Layer",
    version="0.2.0",
    description="""
AI-powered cybersecurity assistant for SOC teams.

## Features
- **MITRE ATT&CK DocQA**: Answer questions about techniques, tactics, mitigations
- **MITRE Mapper**: Map logs/alerts to ATT&CK techniques  
- **MITRE Detect**: Get detection guidance for techniques
- **D3FEND DocQA**: Answer defensive/countermeasure questions
- **Chat**: Conversational interface with memory and context tracking
- **OpenAI-Compatible API**: Connect with Open WebUI and other tools

## Chat Endpoint
Use `/chat` for a conversational experience that remembers context.

## OpenAI-Compatible Endpoint
Use `/v1/chat/completions` to connect with Open WebUI or other OpenAI-compatible clients.
""",
)

# Enable CORS for web UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# Routers
app.include_router(mitre_docqa.router)
app.include_router(mitre_mapper.router)
app.include_router(mitre_detect.router)
app.include_router(d3fend_docqa.router)
app.include_router(query_router.router)
app.include_router(chat.router)

# OpenAI-compatible endpoint (optional)
if HAS_OPENAI_COMPAT:
    app.include_router(openai_compat.router)