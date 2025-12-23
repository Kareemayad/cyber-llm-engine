# src/mitre_expert/api/routers/mitre_detect.py
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from mitre_expert.llm.mitre_detect import (
    build_detection_context,
    answer_mitre_detect,
)

router = APIRouter(
    prefix="/detect",
    tags=["mitre-detect"],
)


class DetectRequest(BaseModel):
    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID (e.g., T1059.001).",
    )
    platform: Optional[str] = Field(
        None,
        description="Optional platform information (e.g., Windows, Linux).",
    )
    available_logs: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of available log sources "
            "(e.g., 'WinEventLog:Security', 'Sysmon', 'azure:signinlogs'). "
            "Used to bias retrieval and guidance toward matching telemetry."
        ),
    )
    topk: int = Field(
        8,
        ge=1,
        le=32,
        description="Number of RAG chunks to retrieve for detection context.",
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
        description="If true, include the raw MITRE detection context in the response.",
    )


class DetectResponse(BaseModel):
    technique_id: str
    answer: str
    context: Optional[str] = None


@router.post("", response_model=DetectResponse)
async def detect_endpoint(payload: DetectRequest) -> DetectResponse:
    """
    MITRE-Detect endpoint.

    Given a technique_id and optional environment context, returns
    detection guidance based on MITRE detection_strategy chunks.

    NOTES:
    - available_logs is forwarded into retrieval to bias toward relevant telemetry.
    - temperature == 0.0 is treated as greedy/deterministic decoding
      (mapped to temperature=None for the underlying LLM wrapper).
    """
    ctx = build_detection_context(
        technique_id=payload.technique_id,
        topk=payload.topk,
        available_logs=payload.available_logs,
    )

    # Treat 0.0 as "greedy / deterministic" (maps to temperature=None for generate_answer)
    if payload.temperature == 0.0:
        temp_for_llm: float | None = None
    else:
        temp_for_llm = payload.temperature

    answer = answer_mitre_detect(
        technique_id=payload.technique_id,
        platform=payload.platform,
        available_logs=payload.available_logs,
        topk=payload.topk,
        temperature=temp_for_llm,
        context=ctx,
    )

    return DetectResponse(
        technique_id=payload.technique_id,
        answer=answer,
        context=ctx if payload.include_context else None,
    )
