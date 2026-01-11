# src/mitre_expert/api/routers/d3fend_docqa.py
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from mitre_expert.llm.d3fend_docqa import (
    build_d3fend_context,
    answer_d3fend_docqa,
)

router = APIRouter(
    prefix="/d3fend/docqa",
    tags=["d3fend-docqa"],
)


class D3FENDDocQARequest(BaseModel):
    question: str = Field(
        ...,
        description="Natural language question to answer using D3FEND RAG chunks.",
    )
    topk: int = Field(
        8,
        ge=1,
        le=32,
        description="Number of D3FEND RAG chunks to retrieve.",
    )
    temperature: float = Field(
        0.3,
        ge=0.0,
        le=1.5,
        description=(
            "Sampling temperature. Use 0.0 for greedy/deterministic decoding; "
            "values > 0 enable sampling."
        ),
    )
    include_context: bool = Field(
        False,
        description="If true, include the raw D3FEND context in the response.",
    )


class D3FENDDocQAResponse(BaseModel):
    answer: str
    context: Optional[str] = None


@router.post("", response_model=D3FENDDocQAResponse)
async def d3fend_docqa_endpoint(payload: D3FENDDocQARequest) -> D3FENDDocQAResponse:
    """
    D3FEND-DocQA endpoint.

    - Retrieves top-k chunks from the D3FEND Chroma collection (d3fend_chunks_v1)
    - Sends them to the LLM with strict "use only provided context" rules
    """
    ctx = build_d3fend_context(
        question=payload.question,
        topk=payload.topk,
    )

    temp_for_llm: float | None = None if payload.temperature == 0.0 else payload.temperature

    answer = answer_d3fend_docqa(
        question=payload.question,
        topk=payload.topk,
        temperature=temp_for_llm,
        context=ctx,
    )

    return D3FENDDocQAResponse(
        answer=answer,
        context=ctx if payload.include_context else None,
    )
