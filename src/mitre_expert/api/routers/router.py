#src/mitre_expert/api/routers/router.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from router.router import route_query

from mitre_expert.llm.mitre_docqa import answer_mitre_docqa
from mitre_expert.llm.mitre_mapper import (
    map_text_to_techniques,
    mapper_result_to_dict,
)
from mitre_expert.llm.mitre_detect import answer_mitre_detect
from mitre_expert.llm.answer_composer import compose_answer
from mitre_expert.rag.query_chroma import (
    resolve_best_technique,
    search_chunks,
    get_chunks,
)

router = APIRouter(prefix="/query", tags=["router"])


class QueryRequest(BaseModel):
    query: str = Field(..., description="User question, log/alert, or CTI text.")

    dataset: str = Field("mitre", description="Dataset to use: 'mitre' | 'd3fend' | 'all'.")
    mode: str = Field("search", description="Retrieval mode: 'search' (semantic) | 'get' (deterministic by filter).")

    technique_id: Optional[str] = Field(None, description="Optional explicit technique_id filter (MITRE-focused).")
    section: Optional[str] = Field(None, description="Optional section filter (e.g., mitigation, description).")

    max_techniques: int = Field(5, ge=1, le=10, description="Maximum number of techniques to return from Mapper.")
    platform: Optional[str] = Field(None, description="Optional platform (e.g., Windows, Linux) for detection context.")
    available_logs: Optional[List[str]] = Field(
        default=None,
        description="Optional list of available log sources (e.g., Windows Security, Sysmon).",
    )
    include_raw_sections: bool = Field(True, description="Include raw docqa/mapping/detection sections in response.")
    topk: int = Field(8, ge=1, le=32, description="Number of chunks to retrieve.")


class QueryResponse(BaseModel):
    question: str
    summary: str
    tactics: List[str]
    techniques: List[Dict[str, Any]]
    sections: Optional[Dict[str, Any]] = None
    route_kind: str
    route_reasons: List[str]


def _normalize_dataset(ds: str) -> str:
    v = (ds or "mitre").strip().lower()
    if v not in ("mitre", "d3fend", "all"):
        raise HTTPException(status_code=400, detail="dataset must be one of: mitre | d3fend | all")
    return v


def _normalize_mode(mode: str) -> str:
    v = (mode or "search").strip().lower()
    if v not in ("search", "get"):
        raise HTTPException(status_code=400, detail="mode must be one of: search | get")
    return v


@router.post("", response_model=QueryResponse)
async def query_endpoint(payload: QueryRequest) -> QueryResponse:
    dataset = _normalize_dataset(payload.dataset)
    mode = _normalize_mode(payload.mode)

    where: Dict[str, Any] = {}
    if payload.technique_id:
        where["technique_id"] = payload.technique_id
    if payload.section:
        where["section"] = payload.section

    # Non-MITRE datasets => retrieval-only
    if dataset in ("d3fend", "all"):
        if mode == "get":
            if dataset == "all":
                raise HTTPException(status_code=400, detail="mode=get is not supported with dataset=all")
            if not where:
                raise HTTPException(
                    status_code=400,
                    detail="mode=get requires at least one filter in 'where' (e.g., section or other metadata keys).",
                )
            res = get_chunks(dataset=dataset, where=where, limit=payload.topk)
        else:
            res = search_chunks(dataset=dataset, query=payload.query, k=payload.topk, where=where or None)

        metas = res.get("metadatas", [[]])[0]
        docs = res.get("documents", [[]])[0]
        dists = res.get("distances", [[]])[0] if res.get("distances") else []
        ids = res.get("ids", [[]])[0]

        chunks_out: List[Dict[str, Any]] = []
        for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
            dist = float(dists[i]) if dists and i < len(dists) else None
            meta = meta or {}
            chunks_out.append(
                {
                    "chunk_id": cid,
                    "dataset": meta.get("dataset", dataset),
                    "section": meta.get("section", meta.get("chunk_type", meta.get("type", "unknown"))),
                    "source": meta.get("source"),
                    "distance": dist,
                    "metadata": meta,
                    "text": doc,
                }
            )

        reasons = [f"retrieval_only: dataset={dataset}", f"mode={mode}"]
        if where:
            reasons.append(f"where={where}")

        return QueryResponse(
            question=payload.query,
            summary=f"Returned {len(chunks_out)} chunks from dataset={dataset} using mode={mode}.",
            tactics=[],
            techniques=chunks_out,
            sections={"chunks": chunks_out} if payload.include_raw_sections else None,
            route_kind="retrieval",
            route_reasons=reasons,
        )

    # MITRE dataset => original pipeline
    # ✅ NEW: pass dataset/mode hints into the router (matches your src/router/router.py signature)
    decision = route_query(payload.query, dataset=dataset, mode=mode)

    mapper_json: Optional[Dict[str, Any]] = None
    docqa_answer: Optional[str] = None
    detect_answer: Optional[str] = None
    top_technique_id: Optional[str] = payload.technique_id

    if decision.kind in ("mapper", "mapper_detect"):
        mapper_result = map_text_to_techniques(text=payload.query, max_techniques=payload.max_techniques)
        mapper_json = mapper_result_to_dict(mapper_result)
        if not top_technique_id and mapper_json.get("techniques"):
            top_technique_id = mapper_json["techniques"][0]["id"]

    if decision.kind == "detect" and not top_technique_id:
        best = resolve_best_technique(payload.query, max_results=3)
        if best:
            top_technique_id = best.id

    if decision.kind in ("detect", "mapper_detect") and top_technique_id:
        detect_answer = answer_mitre_detect(
            technique_id=top_technique_id,
            platform=payload.platform,
            available_logs=payload.available_logs or [],
            topk=payload.topk,
            temperature=0.2,
        )

    if decision.kind == "docqa":
        docqa_answer = answer_mitre_docqa(question=payload.query, topk=payload.topk, temperature=0.2)
    elif decision.kind in ("mapper_detect", "detect"):
        if top_technique_id:
            docqa_answer = answer_mitre_docqa(
                question=f"Explain {top_technique_id} in simple language.",
                topk=payload.topk,
                temperature=0.2,
            )
        else:
            docqa_answer = answer_mitre_docqa(question=payload.query, topk=payload.topk, temperature=0.2)
    elif decision.kind == "mapper" and not detect_answer:
        if top_technique_id:
            docqa_answer = answer_mitre_docqa(
                question=f"Explain {top_technique_id} in simple language.",
                topk=payload.topk,
                temperature=0.2,
            )

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
