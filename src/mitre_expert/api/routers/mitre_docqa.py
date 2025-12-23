# src/mitre_expert/api/routers/mitre_docqa.py
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from mitre_expert.llm.mitre_docqa import (
    build_mitre_context,
    answer_mitre_docqa,
    extract_meta_from_context,
)

router = APIRouter(
    prefix="/docqa",
    tags=["mitre-docqa"],
)


class DocQARequest(BaseModel):
    question: str = Field(
        ...,
        description="Natural language question about MITRE ATT&CK.",
    )
    topk: int = Field(
        8,
        ge=1,
        le=32,
        description="Number of RAG chunks to retrieve.",
    )
    temperature: float = Field(
        0.2,
        ge=0.0,
        le=1.5,
        description=(
            "Sampling temperature. Use 0.0 for greedy/deterministic decoding; "
            "values > 0 enable sampling."
        ),
    )
    include_context: bool = Field(
        False,
        description="If true, include the raw MITRE RAG context in the response (for debugging).",
    )


class DocQAMeta(BaseModel):
    techniques: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)


class DocQAResponse(BaseModel):
    question: str
    answer: str
    context: str | None = None
    meta: Optional[DocQAMeta] = None


@router.post("", response_model=DocQAResponse)
async def docqa_endpoint(payload: DocQARequest) -> DocQAResponse:
    """
    MITRE-DocQA endpoint.

    - Builds MITRE ATT&CK RAG context for the question.
    - Calls the local LLaMA model via answer_mitre_docqa.
    - Extracts structured meta (techniques, tactics, platforms, mitigations)
      from the MITRE context instead of relying on LLM guesses.

    NOTE:
    - temperature == 0.0 is treated as greedy/deterministic decoding.
    - temperature > 0 enables sampling with the given temperature.
    """
    ctx = build_mitre_context(payload.question, topk=payload.topk)

    # Treat 0.0 as "greedy / deterministic" (maps to temperature=None in the LLM wrapper).
    temp_for_llm: float | None
    if payload.temperature == 0.0:
        temp_for_llm = None
    else:
        temp_for_llm = payload.temperature

    answer = answer_mitre_docqa(
        question=payload.question,
        topk=payload.topk,
        temperature=temp_for_llm,
        context=ctx,
    )

    meta_raw = extract_meta_from_context(ctx)
    meta = DocQAMeta(**meta_raw)

    return DocQAResponse(
        question=payload.question,
        answer=answer,
        context=ctx if payload.include_context else None,
        meta=meta,
    )
