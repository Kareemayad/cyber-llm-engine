# src/mitre_expert/llm/mitre_detect.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mitre_expert.llm.local_llm import generate_answer
from mitre_expert.llm.prompts import DETECT_SYSTEM_PROMPT
from mitre_expert.rag.query_chroma import (
    get_mitre_chunks_by_filter,
    search_mitre_chunks,
)


def _split_csv_field(v: object) -> List[str]:
    """
    Normalize a metadata field that might be:
      - CSV string: "a, b, c"
      - list / tuple / set
      - None
      - arbitrary object
    into a clean List[str].
    """
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if x and str(x).strip()]
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    s = str(v).strip()
    return [s] if s else []


def build_detection_context(
    technique_id: str,
    topk: int = 8,
    available_logs: Optional[List[str]] = None,
) -> str:
    """
    Build a MITRE DETECTION CONTEXT block for a given technique.

    Prefer dedicated detection_strategy chunks; fall back to a mix of
    description + procedure examples if detection_strategy is missing.

    If available_logs is provided, we bias retrieval toward chunks whose
    log_source_names overlap those log sources.
    """
    technique_id = (technique_id or "").strip().upper()
    if not technique_id:
        return "No technique_id provided."

    logs = [x.strip() for x in (available_logs or []) if x and x.strip()] or None

    lines: List[str] = []
    lines.append(f"Technique: {technique_id}")
    lines.append("")

    # 1) Try dedicated detection_strategy chunks
    det = get_mitre_chunks_by_filter(
        where={"technique_id": technique_id, "section": "detection_strategy"},
        limit=None,
        logsource=logs,
    )
    det_docs = det.get("documents", [[]])[0]
    det_metas = det.get("metadatas", [[]])[0]

    if det_docs and det_metas:
        for doc, meta in zip(det_docs, det_metas):
            meta = meta or {}
            tname = meta.get("technique_name", "")
            analytic_id = meta.get("analytic_id")
            analytic_name = meta.get("analytic_name")

            header_parts = [technique_id]
            if tname:
                header_parts.append(f"- {tname}")
            header_parts.append("| detection_strategy")
            if analytic_id:
                header_parts.append(f"[{analytic_id}]")
            if analytic_name:
                header_parts.append(f"- {analytic_name}")

            header = " ".join(header_parts)

            lines.append(header)
            lines.append(doc or "")

            # Telemetry hints (helps LLM with Log Sources section)
            log_sources = _split_csv_field(meta.get("log_source_names"))
            data_components = _split_csv_field(meta.get("data_component_ids"))

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
        return "\n".join(lines)

    # 2) Fallback: description + procedure examples (top-k)
    #    This is weaker, but better than nothing.
    #    We search constrained to this technique_id where possible.
    result = search_mitre_chunks(
        query=f"detection or logging for {technique_id}",
        k=topk,
        where={"technique_id": technique_id},
        logsource=logs,
    )
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]

    for doc, meta in zip(docs, metas):
        meta = meta or {}
        tname = meta.get("technique_name", "")
        section = meta.get("section", meta.get("chunk_type", meta.get("type", "unknown")))
        header = f"[{technique_id} {('- ' + tname) if tname else ''} | {section}]"
        lines.append(header)
        lines.append(doc or "")

        # Telemetry hints if present
        log_sources = _split_csv_field(meta.get("log_source_names"))
        data_components = _split_csv_field(meta.get("data_component_ids"))
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
    """
    High-level MITRE-Detect answer function.

    - Builds detection context for a given technique
    - Optionally takes environment information (platform, available_logs)
    - Calls the local LLM with a detection-focused prompt
    """
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

    answer = generate_answer(
        system_prompt=DETECT_SYSTEM_PROMPT,
        user_content=user_content,
        max_new_tokens=768,
        temperature=temperature,
    )

    return answer
