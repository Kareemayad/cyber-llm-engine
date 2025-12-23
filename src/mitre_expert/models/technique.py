# src/mitre_expert/models/technique.py

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from .enums import SectionType


def _coerce_section(value: str) -> SectionType:
    """
    SectionType might be:
      - an Enum (runtime), or
      - a typing alias (e.g., Literal) used only for type-checking.

    This helper keeps runtime safe in both cases.
    """
    try:
        if isinstance(SectionType, type) and issubclass(SectionType, Enum):
            return SectionType(value)  # type: ignore[misc]
    except Exception:
        pass
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
                # item may itself be comma-separated
                items.extend([p.strip() for p in x.split(",")])
            else:
                items.append(str(x).strip())
    else:
        items = [str(raw_platforms).strip()]

    # de-dupe while preserving order
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

    # Telemetry enrichment (from techniques_full_enriched_v2.jsonl)
    # - data_component_ids: list of DC#### related to this technique
    # - log_source_names: unique log source "names" (e.g., "WinEventLog:Security", "auditd:SYSCALL")
    data_component_ids: List[str] = field(default_factory=list)
    log_source_names: List[str] = field(default_factory=list)

    is_sub_technique: bool = False
    sub_technique_of: Optional[str] = None

    description: str = ""

    # Keep the rich nested content for later use / chunking
    procedure_examples: List[Dict[str, Any]] = field(default_factory=list)
    associated_mitigations: List[Dict[str, Any]] = field(default_factory=list)
    associated_detection_strategies: List[Dict[str, Any]] = field(default_factory=list)

    source: str = "mitre_attack"

    # ---------- Constructors / helpers ----------

    @classmethod
    def from_raw(cls, rec: Dict[str, Any]) -> "TechniqueRecord":
        """
        Build a TechniqueRecord from a raw MITRE technique JSON record.
        Handles flattening tactics and normalizing platforms.
        Also passes through enrichment telemetry fields if present.
        """
        # Flatten tactics
        raw_tactics = rec.get("tactics") or []
        tactic_ids = [t.get("tactic_id") for t in raw_tactics if t.get("tactic_id")]
        tactic_names = [t.get("tactic_name") for t in raw_tactics if t.get("tactic_name")]

        platforms = _normalize_platforms(rec.get("platforms"))

        # Telemetry enrichment fields (may not exist in older files)
        data_component_ids = _normalize_str_list(rec.get("data_component_ids"))
        log_source_names = _normalize_str_list(rec.get("log_source_names"))

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
            associated_detection_strategies=rec.get("associated_detection_strategies", []) or [],
            source=rec.get("source", "mitre_attack") or "mitre_attack",
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return asdict(self)

    # ---------- Chunk generation ----------

    def iter_chunks(self) -> Iterable["ChunkRecord"]:
        """
        Yield ChunkRecord objects for:
        - technique description
        - each procedure example
        - each mitigation
        - each detection strategy / analytic

        NOTE: We also attach telemetry metadata (data_component_ids, log_source_names)
        to every chunk so retrieval/filtering can use it.
        """

        # 1) Description chunk
        if self.description.strip():
            yield ChunkRecord(
                chunk_id=f"{self.technique_id}_desc",
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                section=_coerce_section("description"),
                text=self.description.strip(),
                tactic_ids=self.tactic_ids,
                tactic_names=self.tactic_names,
                platforms=self.platforms,
                source="mitre_knowledge_pack_v1",
                data_component_ids=self.data_component_ids,
                log_source_names=self.log_source_names,
            )

        # 2) Procedure examples
        for proc in self.procedure_examples:
            text = _join_nonempty_unique(
                proc.get("mapping_description") or "",
                proc.get("procedure_source_description") or "",
            )
            if not text:
                continue

            src_id = proc.get("procedure_source_id") or "unknown"
            chunk_id = f"{self.technique_id}_proc_{src_id}"
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
                # Extra metadata
                procedure_source_id=proc.get("procedure_source_id"),
                procedure_source_name=proc.get("procedure_source_name"),
                procedure_source_type=proc.get("procedure_source_type"),
            )

        # 3) Mitigations
        for mit in self.associated_mitigations:
            text = _join_nonempty_unique(
                mit.get("mapping_description") or "",
                mit.get("mitigation_source_description") or "",
            )
            if not text:
                continue

            mit_id = mit.get("mitigation_source_id") or "unknown"
            chunk_id = f"{self.technique_id}_mit_{mit_id}"
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
                mitigation_name=mit.get("mitigation_source_name"),
            )

        # 4) Detection strategies / analytics
        for det in self.associated_detection_strategies:
            analytics = det.get("analytics") or []
            for analytic in analytics:
                text = _join_nonempty_unique(
                    det.get("detection_source_name") or "",
                    analytic.get("analytic_description") or "",
                )
                if not text:
                    continue

                analytic_id = analytic.get("analytic_id") or "unknown"
                chunk_id = f"{self.technique_id}_det_{analytic_id}"
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
                    analytic_id=analytic.get("analytic_id"),
                    analytic_name=analytic.get("analytic_name"),
                )


@dataclass
class ChunkRecord:
    """
    One RAG chunk to be embedded & stored in Chroma.

    This is what goes into:
    data/processed/mitre/mitre_chunks_v1.jsonl
    and then into the Chroma collection.
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

    # Telemetry enrichment (copied from technique-level)
    data_component_ids: List[str] = field(default_factory=list)
    log_source_names: List[str] = field(default_factory=list)

    # Optional extra metadata (not always present)
    procedure_source_id: Optional[str] = None
    procedure_source_name: Optional[str] = None
    procedure_source_type: Optional[str] = None

    mitigation_id: Optional[str] = None
    mitigation_name: Optional[str] = None

    analytic_id: Optional[str] = None
    analytic_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return asdict(self)
