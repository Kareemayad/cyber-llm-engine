# src/mitre_expert/llm/mitre_detect.py
"""
MITRE Detection specialist with analytic-level telemetry ranking.

FIX Issue 2: Now prefers analytic-level telemetry over technique-level

IMPORTANT FIX (context-empty bug):
- Do NOT pre-filter Chroma results with logsource=... because user inputs like
  "Security"/"Sysmon" won't exactly match stored values like "WinEventLog:Security".
- Instead: retrieve detection_strategy chunks broadly, then rank locally using
  substring overlap scoring (_overlap_score) which supports partial matches.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from mitre_expert.llm.local_llm import generate_answer
from mitre_expert.llm.prompts import DETECT_SYSTEM_PROMPT
from mitre_expert.rag.query_chroma import (
    get_mitre_chunks_by_filter,
    search_mitre_chunks,
)


def _split_csv_field(v: object) -> List[str]:
    """Normalize metadata field to List[str]."""
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if x and str(x).strip()]
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    s = str(v).strip()
    return [s] if s else []


def _norm_logs(logs: Optional[List[str]]) -> List[str]:
    return [x.strip().lower() for x in (logs or []) if x and x.strip()]


def _overlap_score(chunk_logs: List[str], available_logs: List[str]) -> float:
    """
    Calculate overlap score between chunk logs and available logs.
    - exact match: 1.0
    - substring match: 0.6
    """
    if not chunk_logs or not available_logs:
        return 0.0

    cset = [c.strip().lower() for c in chunk_logs if c and c.strip()]
    aset = available_logs

    score = 0.0
    for c in cset:
        for a in aset:
            if c == a:
                score += 1.0
            elif c in a or a in c:
                score += 0.6
    return score


def _rank_and_trim_chunks(
    docs: List[str],
    metas: List[dict],
    available_logs: Optional[List[str]],
    topk: int,
) -> List[Tuple[str, dict]]:
    """
    Rank chunks by telemetry overlap, return topk.

    FIX Issue 2: Now uses analytic-level telemetry when available.
    """
    if not docs or not metas:
        return []

    alogs = _norm_logs(available_logs)
    scored: List[Tuple[float, int, str, dict]] = []

    for i, (doc, meta) in enumerate(zip(docs, metas)):
        meta = meta or {}

        # Prefer analytic-level telemetry over technique-level
        chunk_logs = (
            _split_csv_field(meta.get("analytic_log_source_names"))
            or _split_csv_field(meta.get("log_source_names"))
        )

        s = _overlap_score(chunk_logs, alogs) if alogs else 0.0
        scored.append((s, i, doc or "", meta))

    # Sort by score desc, then original order
    scored.sort(key=lambda x: (-x[0], x[1]))

    out: List[Tuple[str, dict]] = []
    seen_ids: set[str] = set()

    for _, _, doc, meta in scored:
        cid = str(meta.get("chunk_id") or meta.get("id") or "")
        if cid and cid in seen_ids:
            continue
        if cid:
            seen_ids.add(cid)

        out.append((doc, meta))
        if len(out) >= topk:
            break

    return out


def build_detection_context(
    technique_id: str,
    topk: int = 8,
    available_logs: Optional[List[str]] = None,
) -> str:
    """
    Build MITRE DETECTION CONTEXT for a technique.

    Key behavior:
    - Retrieve detection_strategy chunks broadly (no hard logsource filter).
    - Rank locally by overlap with available_logs (supports partial matches).
    """
    technique_id = (technique_id or "").strip().upper()
    if not technique_id:
        return "No technique_id provided."

    logs = [x.strip() for x in (available_logs or []) if x and x.strip()] or None

    lines: List[str] = []
    lines.append(f"Technique: {technique_id}")
    if logs:
        lines.append(f"Available Logs (caller): {', '.join(logs)}")
    lines.append("")

    # ------------------------------------------------------------------
    # 1) Deterministic: get detection_strategy chunks for this technique.
    #
    # IMPORTANT FIX:
    # Do NOT pass logsource=logs here, because Chroma post-filter expects
    # exact matches and will drop chunks like "WinEventLog:Security" when
    # caller sends "Security". We'll rank locally instead.
    # ------------------------------------------------------------------
    det = get_mitre_chunks_by_filter(
        where={"technique_id": technique_id, "section": "detection_strategy"},
        limit=max(1, int(topk) * 6),  # prefetch more to rank well
        logsource=None,
    )

    det_docs = det.get("documents", [[]])[0] or []
    det_metas = det.get("metadatas", [[]])[0] or []

    picked = _rank_and_trim_chunks(det_docs, det_metas, available_logs=logs, topk=topk)

    if picked:
        for doc, meta in picked:
            meta = meta or {}
            tname = meta.get("technique_name", "")
            analytic_id = meta.get("analytic_id") or meta.get("analytic_stix_id")
            analytic_name = meta.get("analytic_name")

            header_parts = [technique_id]
            if tname:
                header_parts.append(f"- {tname}")
            header_parts.append("| detection_strategy")
            if analytic_id:
                header_parts.append(f"[{analytic_id}]")
            if analytic_name:
                header_parts.append(f"- {analytic_name}")

            lines.append(" ".join(header_parts))
            lines.append(doc.strip() if isinstance(doc, str) else "")

            # Show both analytic-level and technique-level telemetry (prefer analytic)
            analytic_logs = _split_csv_field(meta.get("analytic_log_source_names"))
            analytic_dcs = _split_csv_field(meta.get("analytic_data_component_ids"))

            tech_logs = _split_csv_field(meta.get("log_source_names"))
            tech_dcs = _split_csv_field(meta.get("data_component_ids"))

            log_sources = analytic_logs or tech_logs
            data_components = analytic_dcs or tech_dcs

            tel_lines: List[str] = []
            if log_sources:
                source_label = "Analytic" if analytic_logs else "Technique"
                tel_lines.append(
                    f"Log sources ({source_label}): " + ", ".join(sorted(set(log_sources)))
                )
            if data_components:
                source_label = "Analytic" if analytic_dcs else "Technique"
                tel_lines.append(
                    f"Data components ({source_label}): " + ", ".join(sorted(set(data_components)))
                )

            if tel_lines:
                lines.append("")
                lines.append("Telemetry:")
                for tl in tel_lines:
                    lines.append(f"- {tl}")

            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 2) Fallback: semantic search inside the technique
    #
    # IMPORTANT FIX:
    # Again: no logsource=logs hard filter; rank locally.
    # ------------------------------------------------------------------
    result = search_mitre_chunks(
        query=f"detection strategy analytics logs telemetry for {technique_id}",
        k=max(int(topk) * 6, 12),
        where={"technique_id": technique_id},
        logsource=None,
    )

    docs = result.get("documents", [[]])[0] or []
    metas = result.get("metadatas", [[]])[0] or []

    picked2 = _rank_and_trim_chunks(docs, metas, available_logs=logs, topk=topk)

    for doc, meta in picked2:
        meta = meta or {}
        tname = meta.get("technique_name", "")
        section = meta.get("section", meta.get("chunk_type", meta.get("type", "unknown")))
        header = f"[{technique_id}{(' - ' + tname) if tname else ''} | {section}]"
        lines.append(header)
        lines.append(doc.strip() if isinstance(doc, str) else "")

        analytic_logs = _split_csv_field(meta.get("analytic_log_source_names"))
        analytic_dcs = _split_csv_field(meta.get("analytic_data_component_ids"))
        tech_logs = _split_csv_field(meta.get("log_source_names"))
        tech_dcs = _split_csv_field(meta.get("data_component_ids"))

        log_sources = analytic_logs or tech_logs
        data_components = analytic_dcs or tech_dcs

        tel_lines: List[str] = []
        if log_sources:
            tel_lines.append("Log sources: " + ", ".join(sorted(set(log_sources))))
        if data_components:
            tel_lines.append("Data components: " + ", ".join(sorted(set(data_components))))

        if tel_lines:
            lines.append("")
            lines.append("Telemetry:")
            for tl in tel_lines:
                lines.append(f"- {tl}")

        lines.append("")

    if len(lines) <= 2:
        lines.append("No detection-specific content found in MITRE chunks for this technique.")

    return "\n".join(lines)


def answer_mitre_detect(
    technique_id: str,
    platform: Optional[str] = None,
    available_logs: Optional[List[str]] = None,
    topk: int = 8,
    temperature: float = 0.2,
    context: Optional[str] = None,
) -> str:
    """High-level MITRE-Detect answer function."""
    technique_id = (technique_id or "").strip().upper()

    if context is None:
        context = build_detection_context(
            technique_id=technique_id,
            topk=topk,
            available_logs=available_logs,
        )

    platform = (platform or "").strip()
    logs = [x.strip() for x in (available_logs or []) if x and x.strip()]

    env_lines: List[str] = []
    if platform:
        env_lines.append(f"- platform: {platform}")
    if logs:
        env_lines.append(f"- available_logs: {', '.join(logs)}")
    env_block = "\n".join(env_lines) if env_lines else "None specified."

    user_content = f"""
You are a SOC detection engineer.

You are given:
- A MITRE ATT&CK technique ID.
- Environment context (platform and available log sources).
- MITRE DETECTION CONTEXT that may contain analytics, detection strategies,
  and related descriptions.

STRICT RULES:
- You MUST use ONLY the information explicitly present in the MITRE DETECTION CONTEXT.
- Do NOT invent specific event IDs, products, or tools that are not present in the context.
- If the context does not specify a detail, say so clearly.
- Prefer detection ideas that align with the given ENVIRONMENT (platform / available_logs);
  if the context mentions telemetry that is NOT available, call that out explicitly.

TASK:
1. Briefly restate the detection goal for this technique in 1–2 sentences.
2. Under a section **Log Sources**, list the main types of telemetry/logs that are
   relevant to detecting this technique, based on the context.
3. Under a section **Detection Ideas**, provide 2–5 high-level detection ideas or
   patterns that could be implemented, using ONLY the information in the context.
4. If the context is weak or does not provide detection details, explain that explicitly
   and suggest that additional data (e.g., Sigma rules, product documentation) is required.

ENVIRONMENT:
{env_block}

MITRE DETECTION CONTEXT:
{context}

TECHNIQUE_ID:
{technique_id}
""".strip()

    return generate_answer(
        system_prompt=DETECT_SYSTEM_PROMPT,
        user_content=user_content,
        max_new_tokens=768,
        temperature=temperature,
    )
