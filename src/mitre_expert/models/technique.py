# src/mitre_expert/models/technique.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .enums import SectionType
from typing import get_args


_VALID_SECTIONS = set(get_args(SectionType))

def _coerce_section(value: str) -> SectionType:
    """
    SectionType is a Literal type used for type checking only.
    At runtime we do NOT validate; we just return the string.
    """
    return value  # type: ignore[return-value]

def _normalize_platforms(raw_platforms: Any) -> List[str]:
    """
    Normalize platforms into a clean list.

    Handles:
      - "Windows, Linux, macOS" (comma-separated string)
      - ["Windows", "Linux", "macOS"]
      - ["Windows, Linux"] (list items that are themselves comma-separated)
    """
    if raw_platforms is None:
        return []

    items: List[str] = []

    if isinstance(raw_platforms, str):
        items = [p.strip() for p in raw_platforms.split(",")]
    elif isinstance(raw_platforms, (list, tuple, set)):
        for x in raw_platforms:
            if x is None:
                continue
            if isinstance(x, str):
                items.extend([p.strip() for p in x.split(",")])
            else:
                items.append(str(x).strip())
    else:
        items = [str(raw_platforms).strip()]

    seen: set[str] = set()
    out: List[str] = []
    for p in items:
        if not p:
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _normalize_str_list(raw: Any) -> List[str]:
    """
    Normalize into a clean list[str] (dedupe, keep order).
    Accepts list/tuple/set, comma-separated string, None.
    """
    if raw is None:
        return []

    items: List[str] = []
    if isinstance(raw, str):
        items = [x.strip() for x in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        for x in raw:
            if x is None:
                continue
            if isinstance(x, str):
                items.append(x.strip())
            else:
                items.append(str(x).strip())
    else:
        items = [str(raw).strip()]

    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        if not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _join_nonempty_unique(*parts: str) -> str:
    """
    Join text parts with spacing, removing empties and exact duplicates.
    Keeps order.
    """
    seen: set[str] = set()
    out: List[str] = []
    for p in parts:
        p2 = (p or "").strip()
        if not p2:
            continue
        if p2 in seen:
            continue
        seen.add(p2)
        out.append(p2)
    return "\n\n".join(out)


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        x2 = (x or "").strip()
        if not x2:
            continue
        if x2 in seen:
            continue
        seen.add(x2)
        out.append(x2)
    return out


def _extract_telemetry_from_detection_strategies(detection_strategies: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """
    Compute technique-level telemetry from the NEW structure:
      detection_strategies[] -> analytics[] -> log_source_references[]
    Returns (data_component_ids, log_source_names).
    """
    dc_ids: List[str] = []
    ls_names: List[str] = []

    for ds in detection_strategies or []:
        for an in (ds.get("analytics") or []):
            for lr in (an.get("log_source_references") or []):
                if not isinstance(lr, dict):
                    continue
                dcid = (lr.get("data_component_id") or "").strip()
                ls = (lr.get("log_source_name") or "").strip()
                if dcid:
                    dc_ids.append(dcid)
                if ls:
                    ls_names.append(ls)

    return _dedupe_preserve_order(dc_ids), _dedupe_preserve_order(ls_names)


def _sanitize_chunk_id(raw_id: str) -> str:
    """
    Sanitize a string for use in chunk IDs.
    Removes/replaces problematic characters.
    """
    import re
    # Replace spaces and special chars with underscores
    sanitized = re.sub(r"[^\w\-.]", "_", raw_id)
    # Collapse multiple underscores
    sanitized = re.sub(r"_+", "_", sanitized)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip("_")
    return sanitized or "unknown"


@dataclass
class TechniqueRecord:
    """
    Canonical internal representation of a MITRE ATT&CK technique.

    This is the normalized form we will write to:
    data/processed/mitre/mitre_knowledge_pack_v1.jsonl
    """

    technique_id: str
    technique_name: str

    domain: str = "enterprise-attack"
    url: Optional[str] = None

    tactic_ids: List[str] = field(default_factory=list)
    tactic_names: List[str] = field(default_factory=list)

    platforms: List[str] = field(default_factory=list)

    # Technique-level telemetry enrichment
    data_component_ids: List[str] = field(default_factory=list)
    log_source_names: List[str] = field(default_factory=list)

    is_sub_technique: bool = False
    sub_technique_of: Optional[str] = None

    description: str = ""

    # Keep the rich nested content for later use / chunking
    procedure_examples: List[Dict[str, Any]] = field(default_factory=list)
    associated_mitigations: List[Dict[str, Any]] = field(default_factory=list)

    # NEW canonical field name (but supports old key too)
    detection_strategies: List[Dict[str, Any]] = field(default_factory=list)

    source: str = "mitre_attack"

    # ---------- Constructors / helpers ----------

    @classmethod
    def from_raw(cls, rec: Dict[str, Any]) -> "TechniqueRecord":
        """
        Build a TechniqueRecord from a raw MITRE technique JSON record.

        IMPORTANT:
        - Supports BOTH old and new detection strategy shapes:
          - old: associated_detection_strategies
          - new: detection_strategies

        - Telemetry fields:
          - Prefer explicit data_component_ids/log_source_names if provided
          - Otherwise compute from detection_strategies (new structure)
        """
        raw_tactics = rec.get("tactics") or []
        tactic_ids = [t.get("tactic_id") for t in raw_tactics if isinstance(t, dict) and t.get("tactic_id")]
        tactic_names = [t.get("tactic_name") for t in raw_tactics if isinstance(t, dict) and t.get("tactic_name")]

        platforms = _normalize_platforms(rec.get("platforms"))

        detection_strategies = rec.get("detection_strategies") or []
        if not detection_strategies:
            detection_strategies = rec.get("associated_detection_strategies") or []

        data_component_ids = _normalize_str_list(rec.get("data_component_ids"))
        log_source_names = _normalize_str_list(rec.get("log_source_names"))

        if (not data_component_ids or not log_source_names) and detection_strategies:
            dc2, ls2 = _extract_telemetry_from_detection_strategies(detection_strategies)
            if not data_component_ids:
                data_component_ids = dc2
            if not log_source_names:
                log_source_names = ls2

        return cls(
            technique_id=rec["technique_id"],
            technique_name=rec["technique_name"],
            domain=rec.get("domain", "enterprise-attack"),
            url=rec.get("url"),
            tactic_ids=tactic_ids,
            tactic_names=tactic_names,
            platforms=platforms,
            data_component_ids=data_component_ids,
            log_source_names=log_source_names,
            is_sub_technique=bool(rec.get("is_sub_technique", False)),
            sub_technique_of=rec.get("sub_technique_of"),
            description=rec.get("description", "") or "",
            procedure_examples=rec.get("procedure_examples", []) or [],
            associated_mitigations=rec.get("associated_mitigations", []) or [],
            detection_strategies=detection_strategies or [],
            source=rec.get("source", "mitre_attack") or "mitre_attack",
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # ---------- Chunk generation ----------

    def iter_chunks(self) -> Iterable["ChunkRecord"]:
        """
        Yield ChunkRecord objects for:
        - technique description
        - each procedure example
        - each mitigation
        - each detection strategy / analytic

        Detection chunks are now MUCH higher-quality because they include
        log_source_references (name + channel + data component IDs) inside the chunk
        AND in metadata fields.
        """

        # 1) Description chunk
        if self.description.strip():
            # NEW: Include technique overview in description
            desc_parts = [self.description.strip()]
            
            # Add platforms context
            if self.platforms:
                desc_parts.append(f"Platforms: {', '.join(self.platforms)}")
            
            # Add tactics context
            if self.tactic_names:
                desc_parts.append(f"Tactics: {', '.join(self.tactic_names)}")
            
            yield ChunkRecord(
                chunk_id=f"{self.technique_id}_desc",
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("description"),
                text="\n\n".join(desc_parts),
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
            )

        # 2) Procedure examples
        for i, proc in enumerate(self.procedure_examples):
            if not isinstance(proc, dict):
                continue

            text = _join_nonempty_unique(
                proc.get("mapping_description") or "",
                proc.get("procedure_source_description") or "",
            )
            if not text:
                continue

            src_id = proc.get("procedure_source_id") or f"idx{i}"
            src_name = proc.get("procedure_source_name") or ""
            src_type = proc.get("procedure_source_type") or ""
            
            # NEW: Add context header to procedure text
            header_parts = []
            if src_name:
                header_parts.append(src_name)
            if src_type:
                header_parts.append(f"({src_type})")
            
            if header_parts:
                text = f"{' '.join(header_parts)}:\n\n{text}"
            
            chunk_id = f"{self.technique_id}_proc_{_sanitize_chunk_id(src_id)}"
            yield ChunkRecord(
                chunk_id=chunk_id,
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("procedure_example"),
                text=text,
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
                procedure_source_id=proc.get("procedure_source_id"),
                procedure_source_name=src_name,
                procedure_source_type=src_type,
            )

        # 3) Mitigations
        for i, mit in enumerate(self.associated_mitigations):
            if not isinstance(mit, dict):
                continue

            text = _join_nonempty_unique(
                mit.get("mapping_description") or "",
                mit.get("mitigation_source_description") or "",
            )
            if not text:
                continue

            mit_id = mit.get("mitigation_source_id") or f"idx{i}"
            mit_name = mit.get("mitigation_source_name") or ""
            
            # NEW: Add mitigation header for better context
            if mit_name:
                text = f"{mit_id} - {mit_name}:\n\n{text}"
            elif mit_id:
                text = f"{mit_id}:\n\n{text}"
            
            chunk_id = f"{self.technique_id}_mit_{_sanitize_chunk_id(mit_id)}"
            yield ChunkRecord(
                chunk_id=chunk_id,
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("mitigation"),
                text=text,
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
                mitigation_id=mit.get("mitigation_source_id"),
                mitigation_name=mit_name,
            )

        # 4) Detection strategies / analytics
        seen_analytic_keys: set[str] = set()  # NEW: Prevent duplicate chunks
        
        for ds in self.detection_strategies or []:
            if not isinstance(ds, dict):
                continue

            ds_name = (ds.get("detection_strategy_name") or ds.get("name") or "").strip()
            ds_stix = (ds.get("detection_strategy_stix_id") or ds.get("stix_id") or "").strip()

            for an in (ds.get("analytics") or []):
                if not isinstance(an, dict):
                    continue

                an_name = (an.get("analytic_name") or an.get("name") or "").strip()
                an_stix = (an.get("analytic_stix_id") or an.get("stix_id") or "").strip()
                an_desc = (an.get("analytic_description") or an.get("description") or "").strip()

                # NEW: Dedupe by analytic key
                an_key = an_stix or an_name or "unknown"
                if an_key in seen_analytic_keys:
                    continue
                seen_analytic_keys.add(an_key)

                logrefs = an.get("log_source_references") or an.get("x_mitre_log_source_references") or []
                lr_lines: List[str] = []
                an_dc_ids: List[str] = []
                an_ls_names: List[str] = []

                cleaned_logrefs: List[Dict[str, Any]] = []
                for lr in logrefs:
                    if not isinstance(lr, dict):
                        continue

                    dcid = (lr.get("data_component_id") or lr.get("data_component") or "").strip()
                    dcstix = (lr.get("data_component_stix_id") or lr.get("x_mitre_data_component_ref") or "").strip()
                    ls = (lr.get("log_source_name") or lr.get("name") or "").strip()
                    ch = (lr.get("log_source_channel") or lr.get("channel") or "").strip()

                    # Keep cleaned reference for metadata
                    cleaned = {
                        "data_component_id": dcid,
                        "data_component_stix_id": dcstix,
                        "log_source_name": ls,
                        "log_source_channel": ch,
                    }
                    cleaned_logrefs.append(cleaned)

                    if dcid:
                        an_dc_ids.append(dcid)
                    if ls:
                        an_ls_names.append(ls)

                    parts = [p for p in [dcid or dcstix, ls, ch] if p]
                    if parts:
                        lr_lines.append(" - " + " / ".join(parts))

                an_dc_ids = _dedupe_preserve_order(an_dc_ids)
                an_ls_names = _dedupe_preserve_order(an_ls_names)

                logref_block = ""
                if lr_lines:
                    logref_block = "Log Source References:\n" + "\n".join(lr_lines)

                # NEW: Improved text structure with technique context
                text_parts = []
                
                # Header with technique context
                text_parts.append(f"Detection for {self.technique_id} - {self.technique_name}")
                
                if ds_name:
                    text_parts.append(f"Detection Strategy: {ds_name}")
                
                if an_name:
                    text_parts.append(f"Analytic: {an_name}")
                
                if an_desc:
                    text_parts.append(f"Description: {an_desc}")
                
                if logref_block:
                    text_parts.append(logref_block)
                
                # NEW: Add telemetry summary for easier matching
                if an_ls_names:
                    text_parts.append(f"Required Log Sources: {', '.join(an_ls_names)}")
                if an_dc_ids:
                    text_parts.append(f"Data Components: {', '.join(an_dc_ids)}")

                text = "\n\n".join(text_parts)

                if not text.strip():
                    continue

                chunk_id = f"{self.technique_id}_det_{_sanitize_chunk_id(an_key)}"

                yield ChunkRecord(
                    chunk_id=chunk_id,
                    technique_id=self.technique_id,
                    technique_name=self.technique_name,
                    section=_coerce_section("detection_strategy"),
                    text=text,
                    tactic_ids=self.tactic_ids,
                    tactic_names=self.tactic_names,
                    platforms=self.platforms,
                    source="mitre_knowledge_pack_v1",
                    data_component_ids=self.data_component_ids,
                    log_source_names=self.log_source_names,
                    detection_strategy_stix_id=ds_stix or None,
                    detection_strategy_name=ds_name or None,
                    analytic_stix_id=an_stix or None,
                    analytic_name=an_name or None,
                    analytic_data_component_ids=an_dc_ids,
                    analytic_log_source_names=an_ls_names,
                    analytic_log_source_references=cleaned_logrefs,
                )
        
        # NEW: 5) Fallback detection chunk if no analytics but has telemetry
        if not self.detection_strategies and (self.data_component_ids or self.log_source_names):
            text_parts = [
                f"Detection for {self.technique_id} - {self.technique_name}",
                "",
                "No specific analytics available.",
            ]
            
            if self.log_source_names:
                text_parts.append(f"Relevant Log Sources: {', '.join(self.log_source_names)}")
            if self.data_component_ids:
                text_parts.append(f"Data Components: {', '.join(self.data_component_ids)}")
            
            yield ChunkRecord(
                chunk_id=f"{self.technique_id}_det_fallback",
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("detection_strategy"),
                text="\n\n".join(text_parts),
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
            )


@dataclass
class ChunkRecord:
    """
    One RAG chunk to be embedded & stored in Chroma.

    Goes into:
      data/processed/mitre/mitre_chunks_v1.jsonl
    """

    chunk_id: str
    technique_id: str
    technique_name: str

    section: SectionType
    text: str

    tactic_ids: List[str] = field(default_factory=list)
    tactic_names: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)

    source: str = "mitre_knowledge_pack_v1"

    # Technique-level telemetry enrichment
    data_component_ids: List[str] = field(default_factory=list)
    log_source_names: List[str] = field(default_factory=list)

    # Optional extra metadata
    procedure_source_id: Optional[str] = None
    procedure_source_name: Optional[str] = None
    procedure_source_type: Optional[str] = None

    mitigation_id: Optional[str] = None
    mitigation_name: Optional[str] = None

    # Detection metadata
    detection_strategy_stix_id: Optional[str] = None
    detection_strategy_name: Optional[str] = None

    analytic_stix_id: Optional[str] = None
    analytic_name: Optional[str] = None

    # Analytic-level telemetry grounding
    analytic_data_component_ids: List[str] = field(default_factory=list)
    analytic_log_source_names: List[str] = field(default_factory=list)
    analytic_log_source_references: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)