# src/mitre_expert/api/main.py
from __future__ import annotations

from fastapi import FastAPI

from mitre_expert.api.routers import (
    mitre_docqa,
    mitre_mapper,
    mitre_detect,
    router as query_router,
)

app = FastAPI(
    title="Cyber LLM Engine – MITRE Expert Layer",
    version="0.1.0",
)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# Routers
app.include_router(mitre_docqa.router)
app.include_router(mitre_mapper.router)
app.include_router(mitre_detect.router)
app.include_router(query_router.router)
