# src/mitre_expert/models/technique.py
"""
Enhanced MITRE ATT&CK Technique Data Model and Chunking.

IMPROVEMENTS:
1. Better chunk text with contextual headers
2. Chunk quality scoring for prioritization
3. Overlapping context between chunks
4. Deduplication and normalization
5. Richer metadata for filtering
6. Summary chunks for technique overview
7. Cross-reference chunks linking related techniques
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .enums import SectionType
from typing import get_args


_VALID_SECTIONS = set(get_args(SectionType))


def _coerce_section(value: str) -> SectionType:
    """SectionType is a Literal type used for type checking only."""
    return value  # type: ignore[return-value]


def _normalize_platforms(raw_platforms: Any) -> List[str]:
    """Normalize platforms into a clean list."""
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
    """Normalize into a clean list[str] (dedupe, keep order)."""
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
    """Join text parts with spacing, removing empties and exact duplicates."""
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


def _extract_telemetry_from_detection_strategies(
    detection_strategies: List[Dict[str, Any]]
) -> Tuple[List[str], List[str]]:
    """Extract technique-level telemetry from detection strategies."""
    dc_ids: List[str] = []
    ls_names: List[str] = []

    for ds in detection_strategies or []:
        for an in ds.get("analytics") or []:
            for lr in an.get("log_source_references") or []:
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
    """Sanitize a string for use in chunk IDs."""
    sanitized = re.sub(r"[^\w\-.]", "_", raw_id)
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("_")
    return sanitized or "unknown"


def _truncate_text(text: str, max_chars: int = 2000) -> str:
    """Truncate text to max characters, keeping complete sentences."""
    if len(text) <= max_chars:
        return text
    
    # Find last sentence boundary before max_chars
    truncated = text[:max_chars]
    last_period = truncated.rfind(". ")
    if last_period > max_chars * 0.5:  # At least half the content
        return truncated[:last_period + 1]
    
    return truncated + "..."


def _score_chunk_quality(text: str, section: str) -> float:
    """
    Score chunk by information density and usefulness.
    
    Higher scores = more valuable chunks for retrieval.
    Score range: 0.0 - 1.0
    """
    if not text:
        return 0.0
    
    score = 0.0
    text_lower = text.lower()
    word_count = len(text.split())
    
    # Base score by length (sweet spot: 100-500 words)
    if 50 <= word_count <= 100:
        score += 0.1
    elif 100 < word_count <= 300:
        score += 0.2
    elif 300 < word_count <= 500:
        score += 0.15
    elif word_count > 500:
        score += 0.1
    
    # Has technique IDs
    if re.search(r'\bT\d{4}(?:\.\d{3})?\b', text):
        score += 0.1
    
    # Has mitigation IDs
    if re.search(r'\bM\d{4}\b', text):
        score += 0.1
    
    # Has specific log sources
    log_sources = [
        'sysmon', 'windows security', 'security log', 'auditd', 
        'event id', 'eventid', 'wineventlog', 'etw'
    ]
    if any(ls in text_lower for ls in log_sources):
        score += 0.15
    
    # Has event IDs (very actionable)
    if re.search(r'\bevent\s*(id)?\s*\d+\b', text_lower):
        score += 0.15
    
    # Has specific tools/commands
    tools = [
        'powershell', 'cmd.exe', 'mimikatz', 'psexec', 'wmic',
        'reg.exe', 'net.exe', 'schtasks', 'certutil', 'bitsadmin'
    ]
    if any(tool in text_lower for tool in tools):
        score += 0.1
    
    # Has detection-relevant keywords
    detection_keywords = [
        'monitor', 'detect', 'look for', 'indicator', 'telemetry',
        'log source', 'data component', 'analytic', 'alert'
    ]
    if any(kw in text_lower for kw in detection_keywords):
        score += 0.1
    
    # Section-specific bonuses
    if section == "detection_strategy":
        score += 0.1  # Detection chunks are high value
    elif section == "procedure_example":
        score += 0.05  # Real examples are useful
    
    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Tactic ID to Name Mapping (for context enrichment)
# ---------------------------------------------------------------------------

TACTIC_ID_TO_NAME = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


def _get_tactic_names(tactic_ids: List[str]) -> List[str]:
    """Convert tactic IDs to names."""
    names = []
    for tid in tactic_ids:
        name = TACTIC_ID_TO_NAME.get(tid.upper())
        if name:
            names.append(name)
    return names


# ---------------------------------------------------------------------------
# Main Data Classes
# ---------------------------------------------------------------------------

@dataclass
class TechniqueRecord:
    """
    Canonical internal representation of a MITRE ATT&CK technique.
    
    Enhanced with:
    - Better metadata extraction
    - Telemetry enrichment
    - Quality scoring support
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

    procedure_examples: List[Dict[str, Any]] = field(default_factory=list)
    associated_mitigations: List[Dict[str, Any]] = field(default_factory=list)
    detection_strategies: List[Dict[str, Any]] = field(default_factory=list)

    source: str = "mitre_attack"

    @classmethod
    def from_raw(cls, rec: Dict[str, Any]) -> "TechniqueRecord":
        """Build a TechniqueRecord from a raw MITRE technique JSON record."""
        raw_tactics = rec.get("tactics") or []
        tactic_ids = [t.get("tactic_id") for t in raw_tactics if isinstance(t, dict) and t.get("tactic_id")]
        tactic_names = [t.get("tactic_name") for t in raw_tactics if isinstance(t, dict) and t.get("tactic_name")]

        # If tactic names not provided, derive from IDs
        if not tactic_names and tactic_ids:
            tactic_names = _get_tactic_names(tactic_ids)

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

    def _build_context_header(self) -> str:
        """
        Build a rich context header to prepend to chunks.
        This helps the LLM understand what technique this chunk belongs to.
        """
        lines = [
            f"MITRE ATT&CK Technique: {self.technique_id} - {self.technique_name}",
        ]
        
        if self.tactic_names:
            lines.append(f"Tactics: {', '.join(self.tactic_names)}")
        elif self.tactic_ids:
            names = _get_tactic_names(self.tactic_ids)
            if names:
                lines.append(f"Tactics: {', '.join(names)}")
        
        if self.platforms:
            lines.append(f"Platforms: {', '.join(self.platforms)}")
        
        if self.is_sub_technique and self.sub_technique_of:
            lines.append(f"Parent Technique: {self.sub_technique_of}")
        
        return "\n".join(lines)

    def _build_telemetry_summary(self) -> str:
        """Build a summary of telemetry requirements."""
        parts = []
        
        if self.log_source_names:
            parts.append(f"Log Sources: {', '.join(self.log_source_names[:5])}")
        
        if self.data_component_ids:
            parts.append(f"Data Components: {', '.join(self.data_component_ids[:5])}")
        
        return "\n".join(parts) if parts else ""

    def iter_chunks(self) -> Iterable["ChunkRecord"]:
        """
        Yield ChunkRecord objects with enhanced context and quality scoring.
        
        Chunk types:
        1. Summary chunk (technique overview)
        2. Description chunk
        3. Procedure example chunks
        4. Mitigation chunks
        5. Detection strategy chunks
        """
        context_header = self._build_context_header()
        telemetry_summary = self._build_telemetry_summary()

        # =====================================================================
        # 1) SUMMARY CHUNK (NEW - High-level overview)
        # =====================================================================
        summary_parts = [
            context_header,
            "",
            "--- Overview ---",
        ]
        
        # Add truncated description
        if self.description.strip():
            desc_preview = _truncate_text(self.description.strip(), max_chars=500)
            summary_parts.append(desc_preview)
        
        # Add mitigation count
        if self.associated_mitigations:
            mit_ids = [m.get("mitigation_source_id", "") for m in self.associated_mitigations if m.get("mitigation_source_id")]
            if mit_ids:
                summary_parts.append(f"\nMitigations: {', '.join(mit_ids[:5])}")
        
        # Add telemetry
        if telemetry_summary:
            summary_parts.append(f"\n{telemetry_summary}")
        
        summary_text = "\n".join(summary_parts)
        summary_quality = _score_chunk_quality(summary_text, "summary")
        
        yield ChunkRecord(
            chunk_id=f"{self.technique_id}_summary",
            technique_id=self.technique_id,
            technique_name=self.technique_name,
            section=_coerce_section("summary"),
            text=summary_text,
            tactic_ids=self.tactic_ids,
            tactic_names=self.tactic_names,
            platforms=self.platforms,
            source="mitre_knowledge_pack_v1",
            data_component_ids=self.data_component_ids,
            log_source_names=self.log_source_names,
            quality_score=summary_quality,
        )

        # =====================================================================
        # 2) DESCRIPTION CHUNK
        # =====================================================================
        if self.description.strip():
            desc_parts = [
                context_header,
                "",
                "--- Description ---",
                self.description.strip(),
            ]
            
            # Add related info
            if self.is_sub_technique and self.sub_technique_of:
                desc_parts.append(f"\nThis is a sub-technique of {self.sub_technique_of}.")
            
            desc_text = "\n".join(desc_parts)
            desc_quality = _score_chunk_quality(desc_text, "description")

            yield ChunkRecord(
                chunk_id=f"{self.technique_id}_desc",
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("description"),
                text=desc_text,
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
                quality_score=desc_quality,
            )

        # =====================================================================
        # 3) PROCEDURE EXAMPLE CHUNKS
        # =====================================================================
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

            # Build rich procedure chunk
            proc_parts = [
                context_header,
                "",
                "--- Procedure Example ---",
            ]
            
            # Add source info
            if src_name:
                type_str = f" ({src_type})" if src_type else ""
                proc_parts.append(f"Source: {src_name}{type_str}")
            
            proc_parts.append("")
            proc_parts.append(text)
            
            proc_text = "\n".join(proc_parts)
            proc_quality = _score_chunk_quality(proc_text, "procedure_example")

            chunk_id = f"{self.technique_id}_proc_{_sanitize_chunk_id(src_id)}"
            
            yield ChunkRecord(
                chunk_id=chunk_id,
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("procedure_example"),
                text=proc_text,
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
                procedure_source_id=proc.get("procedure_source_id"),
                procedure_source_name=src_name,
                procedure_source_type=src_type,
                quality_score=proc_quality,
            )

        # =====================================================================
        # 4) MITIGATION CHUNKS
        # =====================================================================
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

            # Build rich mitigation chunk
            mit_parts = [
                context_header,
                "",
                "--- Mitigation ---",
                f"Mitigation ID: {mit_id}",
            ]
            
            if mit_name:
                mit_parts.append(f"Mitigation Name: {mit_name}")
            
            mit_parts.append("")
            mit_parts.append(text)
            
            mit_text = "\n".join(mit_parts)
            mit_quality = _score_chunk_quality(mit_text, "mitigation")

            chunk_id = f"{self.technique_id}_mit_{_sanitize_chunk_id(mit_id)}"
            
            yield ChunkRecord(
                chunk_id=chunk_id,
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("mitigation"),
                text=mit_text,
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
                mitigation_id=mit.get("mitigation_source_id"),
                mitigation_name=mit_name,
                quality_score=mit_quality,
            )

        # =====================================================================
        # 5) DETECTION STRATEGY CHUNKS
        # =====================================================================
        seen_analytic_keys: set[str] = set()

        for ds in self.detection_strategies or []:
            if not isinstance(ds, dict):
                continue

            ds_name = (ds.get("detection_strategy_name") or ds.get("name") or "").strip()
            ds_stix = (ds.get("detection_strategy_stix_id") or ds.get("stix_id") or "").strip()

            for an in ds.get("analytics") or []:
                if not isinstance(an, dict):
                    continue

                an_name = (an.get("analytic_name") or an.get("name") or "").strip()
                an_stix = (an.get("analytic_stix_id") or an.get("stix_id") or "").strip()
                an_desc = (an.get("analytic_description") or an.get("description") or "").strip()

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

                    parts = [p for p in [ls, ch, dcid or dcstix] if p]
                    if parts:
                        lr_lines.append(f"  • {' / '.join(parts)}")

                an_dc_ids = _dedupe_preserve_order(an_dc_ids)
                an_ls_names = _dedupe_preserve_order(an_ls_names)

                # Build rich detection chunk
                det_parts = [
                    context_header,
                    "",
                    "--- Detection Strategy ---",
                ]

                if ds_name:
                    det_parts.append(f"Strategy: {ds_name}")

                if an_name:
                    det_parts.append(f"Analytic: {an_name}")

                if an_desc:
                    det_parts.append("")
                    det_parts.append(f"Description: {an_desc}")

                if lr_lines:
                    det_parts.append("")
                    det_parts.append("Log Source References:")
                    det_parts.extend(lr_lines)

                if an_ls_names:
                    det_parts.append("")
                    det_parts.append(f"Required Log Sources: {', '.join(an_ls_names)}")

                if an_dc_ids:
                    det_parts.append(f"Data Components: {', '.join(an_dc_ids)}")

                det_text = "\n".join(det_parts)
                
                if not det_text.strip():
                    continue

                det_quality = _score_chunk_quality(det_text, "detection_strategy")
                chunk_id = f"{self.technique_id}_det_{_sanitize_chunk_id(an_key)}"

                yield ChunkRecord(
                    chunk_id=chunk_id,
                    technique_id=self.technique_id,
                    technique_name=self.technique_name,
                    section=_coerce_section("detection_strategy"),
                    text=det_text,
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
                    quality_score=det_quality,
                )

        # =====================================================================
        # 6) FALLBACK DETECTION CHUNK
        # =====================================================================
        if not self.detection_strategies and (self.data_component_ids or self.log_source_names):
            fallback_parts = [
                context_header,
                "",
                "--- Detection Guidance ---",
                "",
                "No specific analytics are documented for this technique.",
                "However, the following telemetry sources may be relevant:",
            ]

            if self.log_source_names:
                fallback_parts.append("")
                fallback_parts.append("Relevant Log Sources:")
                for ls in self.log_source_names[:10]:
                    fallback_parts.append(f"  • {ls}")

            if self.data_component_ids:
                fallback_parts.append("")
                fallback_parts.append("Data Components:")
                for dc in self.data_component_ids[:10]:
                    fallback_parts.append(f"  • {dc}")

            fallback_text = "\n".join(fallback_parts)
            fallback_quality = _score_chunk_quality(fallback_text, "detection_strategy")

            yield ChunkRecord(
                chunk_id=f"{self.technique_id}_det_fallback",
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("detection_strategy"),
                text=fallback_text,
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
                quality_score=fallback_quality,
            )


@dataclass
class ChunkRecord:
    """
    One RAG chunk to be embedded & stored in Chroma.
    
    Enhanced with:
    - Quality score for ranking
    - Richer metadata
    - Better text structure
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

    # Technique-level telemetry
    data_component_ids: List[str] = field(default_factory=list)
    log_source_names: List[str] = field(default_factory=list)

    # Quality score (NEW)
    quality_score: float = 0.0

    # Procedure metadata
    procedure_source_id: Optional[str] = None
    procedure_source_name: Optional[str] = None
    procedure_source_type: Optional[str] = None

    # Mitigation metadata
    mitigation_id: Optional[str] = None
    mitigation_name: Optional[str] = None

    # Detection metadata
    detection_strategy_stix_id: Optional[str] = None
    detection_strategy_name: Optional[str] = None
    analytic_stix_id: Optional[str] = None
    analytic_name: Optional[str] = None
    analytic_data_component_ids: List[str] = field(default_factory=list)
    analytic_log_source_names: List[str] = field(default_factory=list)
    analytic_log_source_references: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_chroma_metadata(self) -> Dict[str, Any]:
        """
        Convert to ChromaDB-compatible metadata.
        
        ChromaDB only supports: str, int, float, bool
        Lists must be converted to comma-separated strings.
        """
        meta = {
            "chunk_id": self.chunk_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "section": self.section,
            "source": self.source,
            "quality_score": self.quality_score,
        }

        # Convert lists to CSV strings
        if self.tactic_ids:
            meta["tactic_ids"] = ",".join(self.tactic_ids)
        if self.tactic_names:
            meta["tactic_names"] = ",".join(self.tactic_names)
        if self.platforms:
            meta["platforms"] = ",".join(self.platforms)
        if self.data_component_ids:
            meta["data_component_ids"] = ",".join(self.data_component_ids)
        if self.log_source_names:
            meta["log_source_names"] = ",".join(self.log_source_names)

        # Optional fields
        if self.procedure_source_id:
            meta["procedure_source_id"] = self.procedure_source_id
        if self.procedure_source_name:
            meta["procedure_source_name"] = self.procedure_source_name
        if self.procedure_source_type:
            meta["procedure_source_type"] = self.procedure_source_type

        if self.mitigation_id:
            meta["mitigation_id"] = self.mitigation_id
        if self.mitigation_name:
            meta["mitigation_name"] = self.mitigation_name

        if self.detection_strategy_stix_id:
            meta["detection_strategy_stix_id"] = self.detection_strategy_stix_id
        if self.detection_strategy_name:
            meta["detection_strategy_name"] = self.detection_strategy_name
        if self.analytic_stix_id:
            meta["analytic_stix_id"] = self.analytic_stix_id
        if self.analytic_name:
            meta["analytic_name"] = self.analytic_name
        if self.analytic_data_component_ids:
            meta["analytic_data_component_ids"] = ",".join(self.analytic_data_component_ids)
        if self.analytic_log_source_names:
            meta["analytic_log_source_names"] = ",".join(self.analytic_log_source_names)

        return meta