# src/mitre_expert/api/routers/router.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from router.router import route_query

from mitre_expert.llm.mitre_docqa import answer_mitre_docqa
from mitre_expert.llm.mitre_mapper import map_text_to_techniques, mapper_result_to_dict
from mitre_expert.llm.mitre_detect import answer_mitre_detect, build_detection_context

# ✅ D3FEND docqa
from mitre_expert.llm.d3fend_docqa import build_d3fend_context, answer_d3fend_docqa

from mitre_expert.rag.query_chroma import resolve_best_technique, search_chunks, get_chunks

# ✅ Composer
from mitre_expert.llm.answer_composer import compose_final_answer, format_composed_answer

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
    answer: str  # ✅ always provide a strong final answer
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


def _chunks_to_out(res: Dict[str, Any], dataset_fallback: str) -> List[Dict[str, Any]]:
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
                "dataset": meta.get("dataset", dataset_fallback),
                "section": meta.get("section", meta.get("chunk_type", meta.get("type", "unknown"))),
                "source": meta.get("source"),
                "distance": dist,
                "metadata": meta,
                "text": doc,
            }
        )
    return chunks_out


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _telemetry_split_by_availability(
    telemetry_log_sources: List[str],
    available_logs: Optional[List[str]],
) -> Tuple[List[str], List[str]]:
    """
    Option A:
    Split telemetry log sources into:
      - available: matches caller available_logs (substring match either direction)
      - missing: everything else
    """
    if not telemetry_log_sources:
        return [], []

    alogs = [_norm(x) for x in (available_logs or []) if x and x.strip()]
    if not alogs:
        # If caller didn't provide available logs, treat all as "available"
        return sorted(set(telemetry_log_sources)), []

    available: List[str] = []
    missing: List[str] = []

    for src in telemetry_log_sources:
        s = _norm(src)
        is_match = False
        for a in alogs:
            # substring match either direction:
            # "security" matches "wineventlog:security"
            # "wineventlog:security" matches "security"
            if not a:
                continue
            if a == s or (a in s) or (s in a):
                is_match = True
                break

        if is_match:
            available.append(src)
        else:
            missing.append(src)

    # stable + dedupe
    available = sorted(set(available))
    missing = sorted(set(missing))
    return available, missing


def _mapper_json_to_composer_shape(mapper_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Your composer expects mapper_data["predictions"] with keys:
      - technique_id, technique_name, confidence, tactics, data_components, log_sources, platforms
    But your mapper endpoint returns mapper_json["techniques"] in a different shape.
    This adapter makes the composer work without modifying answer_composer.py.
    """
    preds: List[Dict[str, Any]] = []
    for t in (mapper_json or {}).get("techniques", []) or []:
        if not isinstance(t, dict):
            continue
        preds.append(
            {
                "technique_id": t.get("id"),
                "technique_name": t.get("name", ""),
                "confidence": t.get("confidence", 0.0),
                "tactics": t.get("tactics", []) or [],
                "data_components": t.get("data_components", []) or [],
                "log_sources": t.get("log_sources", []) or [],
                "platforms": t.get("platforms", []) or [],
            }
        )

    out = dict(mapper_json)
    out["predictions"] = preds
    return out


@router.post("", response_model=QueryResponse)
async def query_endpoint(payload: QueryRequest) -> QueryResponse:
    dataset = _normalize_dataset(payload.dataset)
    mode = _normalize_mode(payload.mode)

    where: Dict[str, Any] = {}
    if payload.technique_id:
        where["technique_id"] = payload.technique_id
    if payload.section:
        where["section"] = payload.section

    # ============================================================
    # dataset=all => retrieval-only semantic merge
    # ============================================================
    if dataset == "all":
        if mode == "get":
            raise HTTPException(status_code=400, detail="mode=get is not supported with dataset=all")

        res = search_chunks(dataset="all", query=payload.query, k=payload.topk, where=where or None)
        chunks_out = _chunks_to_out(res, dataset_fallback="all")

        answer = (
            f"Retrieved {len(chunks_out)} chunks across MITRE + D3FEND.\n"
            f"This mode is retrieval-only (no LLM synthesis). "
            f"Use dataset=mitre or dataset=d3fend for a full DocQA answer."
        )

        reasons = [f"retrieval_only: dataset=all", f"mode={mode}"]
        if where:
            reasons.append(f"where={where}")

        return QueryResponse(
            question=payload.query,
            answer=answer,
            summary=f"Returned {len(chunks_out)} chunks from dataset=all using mode=search.",
            tactics=[],
            techniques=chunks_out,
            sections={"chunks": chunks_out} if payload.include_raw_sections else None,
            route_kind="retrieval",
            route_reasons=reasons,
        )

    # ============================================================
    # dataset=d3fend
    # ============================================================
    if dataset == "d3fend":
        # Deterministic GET
        if mode == "get":
            if not where:
                raise HTTPException(
                    status_code=400,
                    detail="mode=get requires at least one filter in 'where' (e.g., section).",
                )
            res = get_chunks(dataset="d3fend", where=where, limit=payload.topk)
            chunks_out = _chunks_to_out(res, dataset_fallback="d3fend")

            answer = (
                f"Returned {len(chunks_out)} D3FEND chunks using deterministic get(). "
                f"This does not run the LLM. Use mode=search for a full DocQA answer."
            )

            return QueryResponse(
                question=payload.query,
                answer=answer,
                summary=f"Returned {len(chunks_out)} chunks from dataset=d3fend using mode=get.",
                tactics=[],
                techniques=chunks_out,
                sections={"chunks": chunks_out} if payload.include_raw_sections else None,
                route_kind="retrieval",
                route_reasons=[f"retrieval_only: dataset=d3fend", "mode=get", f"where={where}"],
            )

        # LLM DocQA for D3FEND
        decision = route_query(payload.query, dataset="d3fend", mode=mode)

        ctx = build_d3fend_context(question=payload.query, topk=payload.topk)
        ans = answer_d3fend_docqa(
            question=payload.query,
            topk=payload.topk,
            temperature=0.3,
            context=ctx,
        )

        sections: Optional[Dict[str, Any]] = None
        if payload.include_raw_sections:
            sections = {"d3fend_docqa": {"answer": ans, "context": ctx, "topk": payload.topk}}

        return QueryResponse(
            question=payload.query,
            answer=ans,
            summary="Answered using D3FEND RAG + local LLM (DocQA).",
            tactics=[],
            techniques=[],
            sections=sections,
            route_kind=decision.kind,
            route_reasons=decision.reasons,
        )

    # ============================================================
    # MITRE dataset => MITRE pipeline + composition + Option A/C
    # ============================================================
    decision = route_query(payload.query, dataset=dataset, mode=mode)

    mapper_json: Optional[Dict[str, Any]] = None
    docqa_answer: Optional[str] = None
    detect_answer: Optional[str] = None
    detect_context: Optional[str] = None

    top_technique_id: Optional[str] = payload.technique_id

    # ------------------------------------------------------------
    # Option C:
    # Run mapper not only for mapper / mapper_detect,
    # but ALSO for detect if user didn't force technique_id.
    # ------------------------------------------------------------
    need_mapper = decision.kind in ("mapper", "mapper_detect") or (
        decision.kind == "detect" and not payload.technique_id
    )
    if need_mapper:
        mapper_result = map_text_to_techniques(
            text=payload.query,
            max_techniques=min(payload.max_techniques, 5),
        )
        mapper_json = mapper_result_to_dict(mapper_result)

        # pick top technique if user didn't specify
        if not top_technique_id and mapper_json and mapper_json.get("techniques"):
            top_technique_id = mapper_json["techniques"][0].get("id")

    # If detect route without technique_id and mapper didn't produce one, try resolver
    if decision.kind == "detect" and not top_technique_id:
        best = resolve_best_technique(payload.query, max_results=3)
        if best:
            top_technique_id = best.id

    # Detect call (with explicit context so we can surface it + compose from it)
    if decision.kind in ("detect", "mapper_detect") and top_technique_id:
        detect_context = build_detection_context(
            technique_id=top_technique_id,
            topk=payload.topk,
            available_logs=payload.available_logs or [],
        )
        detect_answer = answer_mitre_detect(
            technique_id=top_technique_id,
            platform=payload.platform,
            available_logs=payload.available_logs or [],
            topk=payload.topk,
            temperature=0.2,
            context=detect_context,
        )

    # DocQA call
    if decision.kind == "docqa":
        docqa_answer = answer_mitre_docqa(question=payload.query, topk=payload.topk, temperature=0.2)
    elif decision.kind in ("mapper_detect", "detect"):
        # Explain the technique we ended up using
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

    # ------------------------------------------------------------
    # Compose properly using your existing composer
    # ------------------------------------------------------------
    specialist_answers: Dict[str, Any] = {}

    if mapper_json is not None:
        specialist_answers["mapper"] = _mapper_json_to_composer_shape(mapper_json)

    if detect_answer is not None:
        specialist_answers["detect"] = {
            "answer": detect_answer,
            "context": detect_context or "",
            "technique_id": top_technique_id,
        }

    if docqa_answer is not None:
        specialist_answers["docqa"] = {"answer": docqa_answer}

    composed = compose_final_answer(specialist_answers)

    # ------------------------------------------------------------
    # Option A:
    # add an explicit "Available vs Missing" telemetry block
    # ------------------------------------------------------------
    telemetry = composed.get("telemetry", {}) or {}
    all_log_sources: List[str] = telemetry.get("log_sources", []) or []
    available_ls, missing_ls = _telemetry_split_by_availability(all_log_sources, payload.available_logs)

    telemetry_block_lines: List[str] = []
    if all_log_sources:
        telemetry_block_lines.append("## Telemetry Fit (Available vs Missing)")
        telemetry_block_lines.append("")

        if available_ls:
            telemetry_block_lines.append("### Available (matches your environment)")
            for x in available_ls:
                telemetry_block_lines.append(f"- {x}")
            telemetry_block_lines.append("")

        if missing_ls:
            telemetry_block_lines.append("### Missing (mentioned by ATT&CK analytics but not in your environment)")
            for x in missing_ls:
                telemetry_block_lines.append(f"- {x}")
            telemetry_block_lines.append("")

    base_final = format_composed_answer(composed).strip()
    final_text = "\n".join(
        [block for block in ["\n".join(telemetry_block_lines).strip(), base_final] if block]
    ).strip()

    # Extract top-level lists for API compatibility
    tactics: List[str] = composed.get("tactics", []) or []
    techniques: List[Dict[str, Any]] = composed.get("techniques", []) or []

    sections: Optional[Dict[str, Any]] = None
    if payload.include_raw_sections:
        sections = {
            "mapper": mapper_json,
            "detect": {"technique_id": top_technique_id, "answer": detect_answer, "context": detect_context}
            if detect_answer
            else None,
            "docqa": {"answer": docqa_answer} if docqa_answer else None,
            "composed": composed,
        }

    summary_bits: List[str] = [f"route={decision.kind}"]
    if top_technique_id:
        summary_bits.append(f"technique={top_technique_id}")
    summary = " | ".join(summary_bits)

    return QueryResponse(
        question=payload.query,
        answer=final_text if final_text else (docqa_answer or detect_answer or "No answer produced."),
        summary=summary,
        tactics=tactics,
        techniques=techniques,
        sections=sections,
        route_kind=decision.kind,
        route_reasons=decision.reasons,
    )
