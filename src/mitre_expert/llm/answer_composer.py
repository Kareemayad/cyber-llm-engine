# src/mitre_expert/llm/answer_composer.py
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _dedupe_str_list(values: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for v in values:
        if not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def compose_answer(
    question: str,
    mapper_json: Optional[Dict[str, Any]] = None,
    detect_answer: Optional[str] = None,
    docqa_answer: Optional[str] = None,
    primary_technique_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compose a unified response from:
      - MITRE-Mapper (mapper_json)
      - MITRE-Detect (detect_answer)
      - MITRE-DocQA (docqa_answer)

    Returns a dict with:
      - question: original question
      - summary: short human-readable summary
      - tactics: list of tactic IDs (from Mapper if available)
      - techniques: list of {id, name, confidence}
      - sections: raw sections (mapping/docqa/detection) for UI/debug
    """
    sections: Dict[str, Any] = {}
    tactics: List[str] = []

    # We'll accumulate techniques in a dict keyed by normalized ID
    techniques_by_id: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Attach raw sections
    # ------------------------------------------------------------------
    if mapper_json is not None:
        sections["mapping"] = mapper_json

    if docqa_answer is not None:
        sections["docqa"] = {"answer": docqa_answer}

    if detect_answer is not None:
        sections["detection"] = {"answer": detect_answer}

    # ------------------------------------------------------------------
    # Derive techniques & tactics from Mapper first (most reliable)
    # ------------------------------------------------------------------
    if mapper_json is not None:
        mapper_techniques = mapper_json.get("techniques") or []
        mapper_tactics = mapper_json.get("tactics") or []

        # Techniques: pass through from mapper, but dedupe by ID and keep highest confidence
        for t in mapper_techniques:
            raw_id = t.get("id")
            if not raw_id:
                continue

            tid = str(raw_id).strip().upper()
            name = t.get("name", "") or ""
            conf = t.get("confidence", None)
            conf_val: Optional[float] = float(conf) if conf is not None else None

            existing = techniques_by_id.get(tid)
            if existing is None:
                techniques_by_id[tid] = {
                    "id": tid,
                    "name": name,
                    "confidence": conf_val,
                }
            else:
                # Keep the highest non-None confidence; update name if previously empty
                existing_conf = existing.get("confidence")
                if conf_val is not None and (existing_conf is None or conf_val > existing_conf):
                    existing["confidence"] = conf_val
                if name and not existing.get("name"):
                    existing["name"] = name

        # Tactics as a deduped list
        if isinstance(mapper_tactics, list):
            tactics = _dedupe_str_list([str(x).strip() for x in mapper_tactics if x])

    # ------------------------------------------------------------------
    # If no techniques came from Mapper, but we know a primary technique
    # (e.g., Detect-only route), add it with high confidence.
    # ------------------------------------------------------------------
    if not techniques_by_id and primary_technique_id:
        tid = str(primary_technique_id).strip().upper()
        if tid:
            techniques_by_id[tid] = {
                "id": tid,
                "name": "",
                "confidence": 1.0,
            }

    # Freeze techniques into a stable list (preserve insertion order)
    techniques: List[Dict[str, Any]] = list(techniques_by_id.values())

    # ------------------------------------------------------------------
    # Build a short, human-readable summary
    # ------------------------------------------------------------------
    has_mapper = mapper_json is not None
    has_detect = detect_answer is not None
    has_docqa = docqa_answer is not None

    # Helper: technique IDs for summary text
    tech_ids = [t["id"] for t in techniques if isinstance(t.get("id"), str)]
    tech_ids_str = ", ".join(tech_ids)

    if has_mapper and has_detect:
        if tech_ids_str:
            summary = (
                f"The query appears related to MITRE techniques: {tech_ids_str}. "
                f"Detection guidance is also provided for these techniques."
            )
        else:
            summary = "The query was mapped to MITRE techniques and includes detection guidance."
    elif has_mapper:
        if tech_ids_str:
            summary = f"The query appears related to MITRE techniques: {tech_ids_str}."
        else:
            summary = "The query was mapped to one or more MITRE techniques."
    elif has_detect:
        if primary_technique_id:
            summary = f"Detection guidance for technique {str(primary_technique_id).strip().upper()}."
        elif tech_ids_str:
            summary = f"Detection guidance for MITRE techniques: {tech_ids_str}."
        else:
            summary = "Detection guidance based on the provided question."
    elif has_docqa:
        summary = "Answer based on MITRE-DocQA."
    else:
        summary = "No specific MITRE techniques or detections could be identified."

    return {
        "question": question,
        "summary": summary,
        "tactics": tactics,
        "techniques": techniques,
        "sections": sections,
    }
