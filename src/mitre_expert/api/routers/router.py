# src/mitre_expert/api/routers/router.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from router.router import route_query
from mitre_expert.llm.mitre_docqa import answer_mitre_docqa
from mitre_expert.llm.mitre_mapper import (
    map_text_to_techniques,
    mapper_result_to_dict,
)
from mitre_expert.llm.mitre_detect import answer_mitre_detect
from mitre_expert.llm.answer_composer import compose_answer
from mitre_expert.rag.query_chroma import resolve_best_technique

router = APIRouter(
    prefix="/query",
    tags=["router"],
)


class QueryRequest(BaseModel):
    query: str = Field(..., description="User question, log/alert, or CTI text.")
    max_techniques: int = Field(
        5,
        ge=1,
        le=10,
        description="Maximum number of techniques to return from Mapper.",
    )
    technique_id: Optional[str] = Field(
        None,
        description=(
            "Optional explicit technique_id for detection (e.g., T1059.001). "
            "If not provided and Mapper is used, we take top technique; "
            "for detect-only routes we try to resolve from the query."
        ),
    )
    platform: Optional[str] = Field(
        None,
        description="Optional platform (e.g., Windows, Linux) for detection context.",
    )
    available_logs: Optional[List[str]] = Field(
        default=None,
        description="Optional list of available log sources (e.g., Windows Security, Sysmon).",
    )
    include_raw_sections: bool = Field(
        True,
        description="If true, include raw docqa/mapping/detection sections in the response.",
    )


class QueryResponse(BaseModel):
    question: str
    summary: str
    tactics: List[str]
    techniques: List[Dict[str, Any]]
    sections: Optional[Dict[str, Any]] = None
    route_kind: str
    route_reasons: List[str]


@router.post("", response_model=QueryResponse)
async def query_endpoint(payload: QueryRequest) -> QueryResponse:
    """
    Unified entrypoint for MITRE Expert Layer.

    - Uses rule-based router to decide which model(s) to call.
    - Optionally chains Mapper -> Detect.
    - Composes a single structured answer.
    """
    decision = route_query(payload.query)

    mapper_json: Optional[Dict[str, Any]] = None
    docqa_answer: Optional[str] = None
    detect_answer: Optional[str] = None

    # Track which technique_id we ended up using (explicit, mapper, or resolver)
    top_technique_id: Optional[str] = payload.technique_id

    # 1) Mapper if needed (mapper / mapper_detect)
    if decision.kind in ("mapper", "mapper_detect"):
        mapper_result = map_text_to_techniques(
            text=payload.query,
            max_techniques=payload.max_techniques,
        )
        mapper_json = mapper_result_to_dict(mapper_result)

        # Use top technique if none explicitly provided
        if not top_technique_id and mapper_json.get("techniques"):
            top_technique_id = mapper_json["techniques"][0]["id"]

    # 2) Technique resolution for detect-only routes (no Mapper, no explicit ID)
    if decision.kind == "detect" and not top_technique_id:
        best = resolve_best_technique(payload.query, max_results=3)
        if best:
            top_technique_id = best.id

    # 3) Detect if needed (detect / mapper_detect) and we have a technique_id
    if decision.kind in ("detect", "mapper_detect") and top_technique_id:
        detect_answer = answer_mitre_detect(
            technique_id=top_technique_id,
            platform=payload.platform,
            available_logs=payload.available_logs or [],
            topk=8,
            temperature=0.2,
        )

    # 4) DocQA:
    #    - For docqa route: answer the original question.
    #    - For mapper_detect / detect: optional enrichment (explain the technique).
    if decision.kind == "docqa":
        docqa_answer = answer_mitre_docqa(
            question=payload.query,
            topk=8,
            temperature=0.2,
        )
    elif decision.kind in ("mapper_detect", "detect"):
        # Optional enrichment: explain the resolved/top technique in simple language
        if top_technique_id:
            docqa_answer = answer_mitre_docqa(
                question=f"Explain {top_technique_id} in simple language.",
                topk=8,
                temperature=0.2,
            )
        else:
            # Fallback: explain the query directly if we couldn't resolve a technique
            docqa_answer = answer_mitre_docqa(
                question=payload.query,
                topk=8,
                temperature=0.2,
            )
    elif decision.kind == "mapper" and not detect_answer:
        # Optional enrichment for pure mapper: explain the top technique
        if top_technique_id:
            docqa_answer = answer_mitre_docqa(
                question=f"Explain {top_technique_id} in simple language.",
                topk=8,
                temperature=0.2,
            )

    # 5) Compose final answer from mapper_json + detect_answer + docqa_answer
    composed = compose_answer(
        question=payload.query,
        mapper_json=mapper_json,
        detect_answer=detect_answer,
        docqa_answer=docqa_answer,
        primary_technique_id=top_technique_id,
    )

    sections = composed.get("sections") if payload.include_raw_sections else None

    return QueryResponse(
        question=composed["question"],
        summary=composed["summary"],
        tactics=composed["tactics"],
        techniques=composed["techniques"],
        sections=sections,
        route_kind=decision.kind,
        route_reasons=decision.reasons,
    )
