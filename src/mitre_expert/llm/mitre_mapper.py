# src/mitre_expert/llm/mitre_mapper.py
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Tuple, Optional

from mitre_expert.models.technique_resolver import (
    resolve_techniques_from_text,
    TechniqueCandidate,
)
from mitre_expert.rag.query_chroma import (
    detect_techniques_from_query,
    get_mitre_chunks_by_filter,
)


@dataclass
class TechniquePrediction:
    id: str
    name: str
    confidence: float
    tactics: List[str]
    # optional useful context
    data_components: List[str]
    log_sources: List[str]


@dataclass
class MapperResult:
    text: str
    tactics: List[str]
    techniques: List[TechniquePrediction]


def _split_csv_field(v: object) -> List[str]:
    """
    Normalize a metadata field that might be:
      - CSV string: "a, b, c"
      - list / tuple / set
      - None
      - arbitrary object
    into a clean List[str] (dedup handled by callers if needed).
    """
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if x and str(x).strip()]
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    s = str(v).strip()
    return [s] if s else []


@lru_cache(maxsize=2048)
def _fetch_technique_meta(technique_id: str) -> Tuple[str, List[str], List[str], List[str]]:
    """
    Fetch technique_name, tactic_ids, data_component_ids, log_source_names for a technique_id
    using MITRE chunks metadata. Cached to avoid repeated Chroma .get() calls.

    Returns:
        (technique_name, tactic_ids, data_component_ids, log_source_names)
    """
    res = get_mitre_chunks_by_filter(where={"technique_id": technique_id}, limit=1)
    metas = res.get("metadatas", [[]])[0]
    if not metas:
        return "", [], [], []

    meta = metas[0] or {}
    name = meta.get("technique_name") or ""

    tactic_ids = _split_csv_field(meta.get("tactic_ids"))

    # these are stored by index_chroma as comma-separated strings
    dc_ids = _split_csv_field(meta.get("data_component_ids") or meta.get("data_components"))
    log_sources = _split_csv_field(meta.get("log_source_names") or meta.get("log_sources"))

    return name, tactic_ids, dc_ids, log_sources


def _combine_scores(
    resolver_cands: List[TechniqueCandidate],
    semantic_cands: List[Tuple[str, float]],
) -> Dict[str, float]:
    scores: Dict[str, float] = {}

    # 1) Resolver scores (0..1)
    for cand in resolver_cands:
        tid = (cand.id or "").upper()
        if not tid:
            continue
        scores[tid] = max(scores.get(tid, 0.0), float(cand.score))

    # 2) Semantic booster (normalized to top semantic score)
    if semantic_cands:
        max_sem = max(float(s) for _, s in semantic_cands) or 1.0
        for tid_raw, sem_raw in semantic_cands:
            tid = (tid_raw or "").upper()
            if not tid:
                continue
            sem_norm = float(sem_raw) / max_sem  # 0..1
            scores[tid] = scores.get(tid, 0.0) + (sem_norm * 0.35)

    return scores


def _apply_priors(
    text: str,
    scores: Dict[str, float],
    observed_log_sources: Optional[List[str]] = None,
    observed_data_components: Optional[List[str]] = None,
) -> Dict[str, float]:
    """
    Lightweight priors to reduce obvious mis-maps.

    We only adjust techniques already present in scores.
    Adds optional "telemetry alignment" signal:
      - If you pass observed_log_sources / observed_data_components, techniques that overlap get a boost.
    """
    q = (text or "").lower()
    out: Dict[str, float] = dict(scores)

    has_url = any(
        k in q for k in ["url", "uri", "domain", "http", "https", "proxy", "firewall", "dns", "user-agent"]
    )
    has_auth = any(
        k in q
        for k in ["login", "logon", "authentication", "failed", "failure", "password", "credential", "sign-in", "signin", "brute"]
    )

    if has_url:
        for tid in list(out.keys()):
            if tid.startswith("T1071.001") or tid == "T1071":
                out[tid] += 0.15
            if tid == "T1016":
                out[tid] -= 0.15

    if has_auth:
        for tid in list(out.keys()):
            if tid.startswith("T1110"):
                out[tid] += 0.12

    # ✅ Telemetry alignment booster
    obs_logs = [x.strip() for x in (observed_log_sources or []) if x and x.strip()]
    obs_dcs = [x.strip().upper() for x in (observed_data_components or []) if x and x.strip()]

    if obs_logs or obs_dcs:
        obs_logs_set = {x.lower() for x in obs_logs}
        obs_dcs_set = {x.upper() for x in obs_dcs}

        for tid in list(out.keys()):
            _, _, dc_ids, log_sources = _fetch_technique_meta(tid)

            have_logs = {x.lower() for x in log_sources}
            have_dcs = {x.upper() for x in dc_ids}

            if obs_logs_set and (obs_logs_set & have_logs):
                out[tid] += 0.18
            if obs_dcs_set and (obs_dcs_set & have_dcs):
                out[tid] += 0.22

            # tiny penalty if you provided constraints and technique has zero overlap at all
            if (obs_logs_set or obs_dcs_set) and not (
                (obs_logs_set & have_logs) or (obs_dcs_set & have_dcs)
            ):
                out[tid] -= 0.05

    # Clamp before normalization
    for tid, s in list(out.items()):
        out[tid] = max(0.0, min(float(s), 2.0))

    return out


def map_text_to_techniques(
    text: str,
    max_techniques: int = 5,
    observed_log_sources: Optional[List[str]] = None,
    observed_data_components: Optional[List[str]] = None,
) -> MapperResult:
    """
    Map a free-text scenario/log/CTI snippet to MITRE techniques + tactics.

    Improvements:
      - deterministic technique resolver
      - semantic booster via Chroma aggregation
      - cached metadata lookup (name/tactics/dc/log sources)
      - priors (URL/proxy/auth)
      - optional telemetry-alignment booster (observed_log_sources / observed_data_components)
    """
    text = (text or "").strip()
    if not text:
        return MapperResult(text=text, tactics=[], techniques=[])

    # 1) Deterministic technique resolver (e.g., rules / patterns)
    resolver_cands = resolve_techniques_from_text(text, max_results=max_techniques)

    # Build a quick id->name map from resolver for name fallback
    resolver_name_by_id: Dict[str, str] = {}
    for cand in resolver_cands:
        tid = (cand.id or "").upper()
        if not tid:
            continue
        if cand.name:
            resolver_name_by_id[tid] = cand.name

    # 2) Semantic candidates from Chroma
    semantic_cands = detect_techniques_from_query(
        query=text,
        detect_k=30,
        max_candidates=max_techniques,
    )

    # 3) Combine scores and apply priors
    raw_scores = _combine_scores(resolver_cands, semantic_cands)
    raw_scores = _apply_priors(
        text,
        raw_scores,
        observed_log_sources=observed_log_sources,
        observed_data_components=observed_data_components,
    )

    if not raw_scores:
        return MapperResult(text=text, tactics=[], techniques=[])

    # 4) Rank and normalize to 0..1 confidence
    sorted_items = sorted(raw_scores.items(), key=lambda kv: kv[1], reverse=True)[:max_techniques]
    max_raw = sorted_items[0][1] or 1.0

    predictions: List[TechniquePrediction] = []
    all_tactics: List[str] = []

    for tid, raw_score in sorted_items:
        tid_norm = tid.upper()
        name, tactic_ids, dc_ids, log_sources = _fetch_technique_meta(tid_norm)

        # If Chroma doesn't have a name yet, fall back to resolver's name (if any)
        if not name:
            name = resolver_name_by_id.get(tid_norm, "")

        confidence = float(raw_score) / max_raw
        confidence = max(0.0, min(confidence, 1.0))

        predictions.append(
            TechniquePrediction(
                id=tid_norm,
                name=name,
                confidence=confidence,
                tactics=tactic_ids,
                data_components=dc_ids,
                log_sources=log_sources,
            )
        )
        all_tactics.extend(tactic_ids)

    # 5) Unique tactics (preserve order)
    seen: set[str] = set()
    unique_tactics: List[str] = []
    for t in all_tactics:
        if t and t not in seen:
            seen.add(t)
            unique_tactics.append(t)

    return MapperResult(text=text, tactics=unique_tactics, techniques=predictions)


def mapper_result_to_dict(result: MapperResult) -> Dict[str, object]:
    """
    Convert MapperResult into a JSON-serializable dict suitable for APIs.
    """
    return {
        "tactics": result.tactics,
        "techniques": [
            {
                "id": t.id,
                "name": t.name,
                "confidence": t.confidence,
                "tactics": t.tactics,
                "data_components": t.data_components,
                "log_sources": t.log_sources,
            }
            for t in result.techniques
        ],
    }
