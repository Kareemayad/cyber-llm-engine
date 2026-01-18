# src/mitre_expert/llm/answer_composer.py
"""
Answer composer that merges outputs from multiple specialists.

Supports mapper outputs in two formats:
1) legacy: {"predictions":[{"technique_id","technique_name","confidence","tactics","log_sources","data_components","platforms"}]}
2) current: {"tactics":[...], "techniques":[{"id","name","confidence","tactics","log_sources","data_components"}]}

Also surfaces telemetry (log_sources, data_components) and platforms if present.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set


def compose_final_answer(specialist_answers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge outputs from multiple MITRE specialists.

    Args:
        specialist_answers: Dict with keys like "mapper", "detect", "docqa"
          - mapper: dict output from mapper_result_to_dict()
          - detect: {"answer": "...", "context": "...", ...} or a raw string
          - docqa:  {"answer": "..."} or a raw string

    Returns:
        Composed response with tactics, techniques, telemetry, platforms, and raw answers
    """
    composed: Dict[str, Any] = {
        "tactics": [],
        "techniques": [],
        "telemetry": {
            "log_sources": set(),
            "data_components": set(),
        },
        "platforms": set(),
        "raw_answers": {},
    }

    # -----------------------------
    # Mapper extraction
    # -----------------------------
    if "mapper" in specialist_answers and specialist_answers["mapper"] is not None:
        mapper_data = specialist_answers["mapper"]
        composed["raw_answers"]["mapper"] = mapper_data

        # 1) Tactics at top-level (your current /mapper output)
        top_tactics = mapper_data.get("tactics")
        if isinstance(top_tactics, list):
            composed["tactics"].extend(top_tactics)

        # 2) New format: mapper_data["techniques"]
        techniques = mapper_data.get("techniques")
        if isinstance(techniques, list) and techniques:
            for tech in techniques:
                if not isinstance(tech, dict):
                    continue

                tech_id = tech.get("id")
                if tech_id:
                    composed["techniques"].append(
                        {
                            "id": tech_id,
                            "name": tech.get("name", "") or "",
                            "confidence": float(tech.get("confidence", 0.0) or 0.0),
                        }
                    )

                # tactics can also be per-technique
                tacts = tech.get("tactics")
                if isinstance(tacts, list):
                    composed["tactics"].extend(tacts)

                # telemetry
                log_sources = tech.get("log_sources")
                if isinstance(log_sources, list):
                    composed["telemetry"]["log_sources"].update([str(x) for x in log_sources if x])

                data_components = tech.get("data_components")
                if isinstance(data_components, list):
                    composed["telemetry"]["data_components"].update([str(x) for x in data_components if x])

                # platforms (if mapper provides them later)
                platforms = tech.get("platforms")
                if isinstance(platforms, list):
                    composed["platforms"].update([str(x) for x in platforms if x])

        # 3) Legacy format: mapper_data["predictions"]
        predictions = mapper_data.get("predictions")
        if isinstance(predictions, list) and predictions:
            for pred in predictions:
                if not isinstance(pred, dict):
                    continue

                tech_id = pred.get("technique_id")
                if tech_id:
                    composed["techniques"].append(
                        {
                            "id": tech_id,
                            "name": pred.get("technique_name", "") or "",
                            "confidence": float(pred.get("confidence", 0.0) or 0.0),
                        }
                    )

                tactics = pred.get("tactics")
                if isinstance(tactics, list):
                    composed["tactics"].extend(tactics)

                log_sources = pred.get("log_sources")
                if isinstance(log_sources, list):
                    composed["telemetry"]["log_sources"].update([str(x) for x in log_sources if x])

                data_components = pred.get("data_components")
                if isinstance(data_components, list):
                    composed["telemetry"]["data_components"].update([str(x) for x in data_components if x])

                platforms = pred.get("platforms")
                if isinstance(platforms, list):
                    composed["platforms"].update([str(x) for x in platforms if x])

    # -----------------------------
    # Detect extraction
    # -----------------------------
    if "detect" in specialist_answers and specialist_answers["detect"] is not None:
        detect_data = specialist_answers["detect"]
        composed["raw_answers"]["detect"] = detect_data

        # allow detect to be string or dict
        if isinstance(detect_data, str):
            _extract_telemetry_from_context(detect_data, composed["telemetry"])
        elif isinstance(detect_data, dict):
            ctx = detect_data.get("context") or ""
            if isinstance(ctx, str) and ctx:
                _extract_telemetry_from_context(ctx, composed["telemetry"])

    # -----------------------------
    # DocQA extraction
    # -----------------------------
    if "docqa" in specialist_answers and specialist_answers["docqa"] is not None:
        docqa_data = specialist_answers["docqa"]
        composed["raw_answers"]["docqa"] = docqa_data

    # -----------------------------
    # Deduplicate + normalize
    # -----------------------------
    # tactics
    seen_tactics: Set[str] = set()
    unique_tactics: List[str] = []
    for t in composed["tactics"]:
        t_name = str(t).strip()
        if t_name and t_name not in seen_tactics:
            seen_tactics.add(t_name)
            unique_tactics.append(t_name)
    composed["tactics"] = sorted(unique_tactics)

    # techniques (dedupe by id, keep max confidence)
    best_by_id: Dict[str, Dict[str, Any]] = {}
    for tech in composed["techniques"]:
        if not isinstance(tech, dict):
            continue
        tid = tech.get("id")
        if not tid:
            continue
        prev = best_by_id.get(tid)
        if prev is None or float(tech.get("confidence", 0.0)) > float(prev.get("confidence", 0.0)):
            best_by_id[tid] = tech
    composed["techniques"] = sorted(best_by_id.values(), key=lambda x: x.get("confidence", 0.0), reverse=True)

    # telemetry sets -> sorted lists
    composed["telemetry"]["log_sources"] = sorted(composed["telemetry"]["log_sources"])
    composed["telemetry"]["data_components"] = sorted(composed["telemetry"]["data_components"])

    # platforms set -> sorted list
    composed["platforms"] = sorted(composed["platforms"])

    return composed


def _extract_telemetry_from_context(context: str, telemetry: Dict[str, Set[str]]) -> None:
    """
    Helper to parse telemetry mentions from detection context.
    Simple extraction - looks for patterns like "Log sources: A, B".
    """
    if not context:
        return

    lines = context.split("\n")
    for line in lines:
        line_lower = line.lower()

        if "log source" in line_lower and ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                sources = [s.strip() for s in parts[1].split(",")]
                telemetry["log_sources"].update(s for s in sources if s)

        if "data component" in line_lower and ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                comps = [c.strip() for c in parts[1].split(",")]
                telemetry["data_components"].update(c for c in comps if c)


def format_composed_answer(composed: Dict[str, Any]) -> str:
    """
    Format composed answer into human-readable text.
    """
    lines: List[str] = []

    # Techniques
    if composed.get("techniques"):
        lines.append("## Identified Techniques")
        for tech in composed["techniques"]:
            tech_id = tech.get("id", "unknown")
            tech_name = tech.get("name", "")
            confidence = tech.get("confidence", 0.0)
            s = f"- **{tech_id}**"
            if tech_name:
                s += f": {tech_name}"
            s += f" (confidence: {confidence:.2f})"
            lines.append(s)
        lines.append("")

    # Tactics
    if composed.get("tactics"):
        lines.append("## Related Tactics")
        for tactic in composed["tactics"]:
            lines.append(f"- {tactic}")
        lines.append("")

    # Telemetry
    telemetry = composed.get("telemetry", {})
    log_sources = telemetry.get("log_sources", [])
    data_components = telemetry.get("data_components", [])

    if log_sources or data_components:
        lines.append("## Required Telemetry")
        if log_sources:
            lines.append("### Log Sources")
            for ls in log_sources:
                lines.append(f"- {ls}")
            lines.append("")
        if data_components:
            lines.append("### Data Components")
            for dc in data_components:
                lines.append(f"- {dc}")
            lines.append("")

    # Platforms
    platforms = composed.get("platforms", [])
    if platforms:
        lines.append("## Platforms")
        lines.append(", ".join(platforms))
        lines.append("")

    # Raw specialist answers
    raw = composed.get("raw_answers", {})

    if "detect" in raw:
        lines.append("## Detection Guidance")
        detect = raw["detect"]
        if isinstance(detect, dict):
            txt = detect.get("answer", "")
        else:
            txt = str(detect)
        if txt:
            lines.append(txt)
        lines.append("")

    if "docqa" in raw:
        lines.append("## Additional Context")
        docqa = raw["docqa"]
        if isinstance(docqa, dict):
            txt = docqa.get("answer", "")
        else:
            txt = str(docqa)
        if txt:
            lines.append(txt)
        lines.append("")

    return "\n".join(lines).strip()
