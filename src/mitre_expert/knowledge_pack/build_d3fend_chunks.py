# src/mitre_expert/knowledge_pack/build_d3fend_chunks.py
"""
Build D3FEND RAG chunks from the normalized defenses JSONL.

Input (hardcoded):
  data/processed/mitre/d3fend_defenses_v1.jsonl

Output (hardcoded):
  data/processed/mitre/d3fend_chunks_v1.jsonl

Chunk types (per defense):
  - definition       : Core definition of the defensive technique
  - kb_article       : Knowledge base article content
  - relations        : D3FEND ontology relations (enables, hardens, etc.)
  - attack_mappings  : Summary of all mapped ATT&CK techniques
  - attack_mapping   : Per-technique mapping (one chunk per ATT&CK technique)

Notes:
  - Defensive against schema drift: tries multiple keys.
  - Extracts ATT&CK technique IDs (Txxxx / Txxxx.xxx) wherever they appear.
  - Per-technique chunks enable better retrieval for "what defends against T1059?"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Hardcoded IO paths (repo-relative)
# ---------------------------------------------------------------------------

IN_JSONL = Path("data/processed/mitre/d3fend_defenses_v1.jsonl")
OUT_JSONL = Path("data/processed/mitre/d3fend_chunks_v1.jsonl")

SOURCE_NAME = "d3fend_chunks_v1"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _as_list(x: Any) -> List[Any]:
    """Normalize value to list."""
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _clean_text(x: Any) -> str:
    """Clean and strip text value."""
    if x is None:
        return ""
    if isinstance(x, str):
        return x.strip()
    return str(x).strip()


def _get_first(d: Dict[str, Any], keys: List[str]) -> Any:
    """Get first non-empty value from dict using multiple possible keys."""
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return None


def _extract_attack_ids(obj: Any) -> List[str]:
    """
    Walk any nested structure and extract ATT&CK technique IDs from strings.
    Returns deduplicated list preserving first occurrence order.
    """
    found: List[str] = []

    def walk(x: Any) -> None:
        if x is None:
            return
        if isinstance(x, str):
            found.extend(TECH_ID_RE.findall(x))
            return
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
            return
        if isinstance(x, list):
            for v in x:
                walk(v)
            return

    walk(obj)

    # Normalize + dedupe preserving order
    norm: List[str] = []
    seen: Set[str] = set()
    for t in found:
        tid = t.upper()
        if tid not in seen:
            seen.add(tid)
            norm.append(tid)
    return norm


def _extract_uri(x: Any) -> Optional[str]:
    """Extract URI from common D3FEND JSON-LD patterns."""
    if isinstance(x, str):
        return x
    if isinstance(x, dict) and "@id" in x and isinstance(x["@id"], str):
        return x["@id"]
    return None


def _summarize_relations(rec: Dict[str, Any]) -> Tuple[str, List[str], List[str]]:
    """
    Build a readable relations summary text.
    
    Returns:
        Tuple of (text, relation_types, related_uris)
    """
    rel_keys = [
        # Common relation keys in JSON-LD
        "d3f:related", "d3f:enables", "d3f:hardens", "d3f:spoofs", "d3f:monitors",
        "d3f:creates", "d3f:produces", "d3f:authenticates", "d3f:analyzes",
        "d3f:validates", "d3f:signs", "d3f:isolates", "d3f:filters",
        "d3f:blocks", "d3f:detects", "d3f:verifies",
        # Normalized variants
        "related", "enables", "hardens", "spoofs", "monitors",
        "creates", "produces", "authenticates", "analyzes",
        "validates", "signs", "isolates", "filters",
        "blocks", "detects", "verifies",
    ]

    lines: List[str] = []
    rel_types: List[str] = []
    related_uris: List[str] = []

    for k in rel_keys:
        if k not in rec:
            continue
        vals = _as_list(rec.get(k))
        uris = []
        for v in vals:
            u = _extract_uri(v)
            if u:
                uris.append(u)
        if not uris:
            continue

        rel_types.append(k)
        related_uris.extend(uris)

        # Format for display
        shown = uris[:12]
        more = f" (+{len(uris)-len(shown)} more)" if len(uris) > len(shown) else ""
        lines.append(f"- {k}: {', '.join(shown)}{more}")

    # Dedupe related_uris preserving order
    seen: Set[str] = set()
    related_uris_dedup: List[str] = []
    for u in related_uris:
        if u not in seen:
            seen.add(u)
            related_uris_dedup.append(u)

    if not lines:
        return "", [], []

    text = "Relations:\n" + "\n".join(lines)
    return text, rel_types, related_uris_dedup


def _extract_kb_references(rec: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract knowledge base references from defense record."""
    kb_refs_raw = _get_first(rec, [
        "kb_reference", "d3f:kb-reference", 
        "kb_references", "d3f:kb-reference-of",
        "raw_properties.d3f:kb-reference",
    ])
    
    if not kb_refs_raw:
        # Try nested in raw_properties
        raw_props = rec.get("raw_properties", {})
        kb_refs_raw = raw_props.get("d3f:kb-reference")
    
    if not kb_refs_raw:
        return []
    
    refs = _as_list(kb_refs_raw)
    result: List[Dict[str, str]] = []
    
    for ref in refs:
        if isinstance(ref, dict):
            result.append({
                "id": ref.get("@id", ""),
                "label": ref.get("rdfs:label", ref.get("label", "")),
                "url": ref.get("d3f:kb-reference-url", ref.get("url", "")),
            })
        elif isinstance(ref, str):
            result.append({"id": ref, "label": "", "url": ""})
    
    return result


# ---------------------------------------------------------------------------
# Attack mapping extraction
# ---------------------------------------------------------------------------

@dataclass
class AttackMapping:
    """Represents a single D3FEND -> ATT&CK mapping."""
    technique_id: str
    technique_label: str
    technique_uri: str
    defense_tactic: str
    defense_artifact: str
    offensive_artifact: str
    attack_tactic: str
    
    def to_text(self, defense_label: str) -> str:
        """Generate readable text for this mapping."""
        lines = [
            f"{defense_label} counters {self.technique_id}",
            "",
        ]
        
        if self.technique_label:
            lines.append(f"ATT&CK Technique: {self.technique_id} - {self.technique_label}")
        else:
            lines.append(f"ATT&CK Technique: {self.technique_id}")
        
        if self.attack_tactic:
            lines.append(f"ATT&CK Tactic: {self.attack_tactic}")
        
        if self.defense_tactic:
            lines.append(f"Defensive Tactic: {self.defense_tactic}")
        
        if self.defense_artifact:
            lines.append(f"Defensive Artifact: {self.defense_artifact}")
        
        if self.offensive_artifact:
            lines.append(f"Offensive Artifact Countered: {self.offensive_artifact}")
        
        return "\n".join(lines)


def _extract_attack_mappings(rec: Dict[str, Any]) -> List[AttackMapping]:
    """
    Extract structured ATT&CK mappings from defense record.
    
    Returns deduplicated list of AttackMapping objects (one per technique).
    """
    raw_mappings = rec.get("attack_mappings", [])
    
    if not raw_mappings:
        return []
    
    # Dedupe by technique ID, keeping first (usually most complete) mapping
    seen_techniques: Set[str] = set()
    mappings: List[AttackMapping] = []
    
    for m in raw_mappings:
        if not isinstance(m, dict):
            continue
        
        tech_id = _clean_text(m.get("attack_technique_id", "")).upper()
        if not tech_id or not TECH_ID_RE.match(tech_id):
            continue
        
        if tech_id in seen_techniques:
            continue
        seen_techniques.add(tech_id)
        
        mappings.append(AttackMapping(
            technique_id=tech_id,
            technique_label=_clean_text(m.get("attack_technique_label", "")),
            technique_uri=_clean_text(m.get("attack_technique_uri", "")),
            defense_tactic=_clean_text(m.get("def_tactic_label", "")),
            defense_artifact=_clean_text(m.get("def_artifact_label", "")),
            offensive_artifact=_clean_text(m.get("off_artifact_label", "")),
            attack_tactic=_clean_text(m.get("attack_tactic_label", "")),
        ))
    
    return mappings


# ---------------------------------------------------------------------------
# Chunk model
# ---------------------------------------------------------------------------

@dataclass
class D3fendChunk:
    """Represents a single RAG chunk for D3FEND."""
    chunk_id: str
    section: str
    text: str

    # Core metadata
    source: str
    d3fend_id: str
    label: str
    uri: str

    # Linked ATT&CK techniques
    attack_techniques: List[str] = field(default_factory=list)
    
    # Relations metadata
    relation_types: List[str] = field(default_factory=list)
    related_uris: List[str] = field(default_factory=list)
    
    # Optional: specific technique for attack_mapping chunks
    primary_attack_technique: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = {
            "chunk_id": self.chunk_id,
            "section": self.section,
            "text": self.text,
            "source": self.source,
            "d3fend_id": self.d3fend_id,
            "label": self.label,
            "uri": self.uri,
            "attack_techniques": self.attack_techniques,
            "relation_types": self.relation_types,
            "related_uris": self.related_uris,
        }
        
        if self.primary_attack_technique:
            d["primary_attack_technique"] = self.primary_attack_technique
        
        return d


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    """Load records from JSONL file."""
    if not path.exists():
        raise FileNotFoundError(f"Input JSONL not found: {path}")
    
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise json.JSONDecodeError(
                    f"Error parsing JSONL on line {i}: {e.msg}", e.doc, e.pos
                )
            if isinstance(obj, dict):
                yield obj


def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    """Write records to JSONL file. Returns count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


# ---------------------------------------------------------------------------
# Chunking logic
# ---------------------------------------------------------------------------

def iter_d3fend_chunks(defense: Dict[str, Any]) -> Iterator[D3fendChunk]:
    """
    Given a single defense record, yield all chunks.
    
    Chunk types:
    - definition: Core definition text
    - kb_article: Knowledge base article
    - relations: D3FEND ontology relations
    - attack_mappings: Summary of all ATT&CK mappings
    - attack_mapping: Per-technique mapping (enables precise retrieval)
    """
    # Extract core identifiers
    d3fend_id = _clean_text(_get_first(defense, [
        "d3fend_id", "d3f:d3fend-id", "id"
    ])) or "UNKNOWN"
    
    label = _clean_text(_get_first(defense, [
        "label", "rdfs:label", "name", "pref_label", "skos:prefLabel"
    ])) or d3fend_id
    
    uri = _clean_text(_get_first(defense, ["uri", "@id"])) or ""

    # Extract content fields
    definition = _clean_text(_get_first(defense, ["definition", "d3f:definition"]))
    
    # KB article might be in raw_properties
    kb_article = _clean_text(_get_first(defense, ["kb_article", "d3f:kb-article"]))
    if not kb_article:
        raw_props = defense.get("raw_properties", {})
        kb_article = _clean_text(raw_props.get("d3f:kb-article", ""))
    
    # KB references
    kb_refs = _extract_kb_references(defense)

    # Relations
    rel_text, rel_types, rel_uris = _summarize_relations(defense)
    
    # Also check raw_properties for relations
    raw_props = defense.get("raw_properties", {})
    if not rel_text:
        rel_text_raw, rel_types_raw, rel_uris_raw = _summarize_relations(raw_props)
        if rel_text_raw:
            rel_text = rel_text_raw
            rel_types = rel_types_raw
            rel_uris = rel_uris_raw

    # Extract all ATT&CK IDs from various sources
    attack_ids = _extract_attack_ids({
        "defense": defense,
        "kb_refs": kb_refs,
    })
    
    # Extract structured attack mappings
    attack_mappings = _extract_attack_mappings(defense)
    
    # Add technique IDs from structured mappings
    for mapping in attack_mappings:
        if mapping.technique_id and mapping.technique_id not in attack_ids:
            attack_ids.append(mapping.technique_id)

    # Common chunk kwargs
    common_kwargs = {
        "source": SOURCE_NAME,
        "d3fend_id": d3fend_id,
        "label": label,
        "uri": uri,
        "relation_types": rel_types,
        "related_uris": rel_uris,
    }

    # -------------------------------------------------------------------------
    # 1) Definition chunk
    # -------------------------------------------------------------------------
    if definition:
        text_parts = [label, "", "Definition:", definition]
        
        # Add types if available
        types = defense.get("types", [])
        if types:
            type_names = [t.split(":")[-1] if ":" in t else t for t in types[:5]]
            text_parts.extend(["", f"Type: {', '.join(type_names)}"])
        
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_def",
            section="definition",
            text="\n".join(text_parts),
            attack_techniques=attack_ids,
            **common_kwargs,
        )

    # -------------------------------------------------------------------------
    # 2) KB Article chunk
    # -------------------------------------------------------------------------
    if kb_article:
        text_parts = [label, "", "Knowledge Base Article:", kb_article]
        
        # Add references if available
        if kb_refs:
            text_parts.extend(["", "References:"])
            for ref in kb_refs[:10]:
                ref_label = ref.get("label") or ref.get("id", "")
                ref_url = ref.get("url", "")
                if ref_label and ref_url:
                    text_parts.append(f"- {ref_label}: {ref_url}")
                elif ref_label:
                    text_parts.append(f"- {ref_label}")
        
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_kb",
            section="kb_article",
            text="\n".join(text_parts),
            attack_techniques=attack_ids,
            **common_kwargs,
        )

    # -------------------------------------------------------------------------
    # 3) Relations chunk
    # -------------------------------------------------------------------------
    if rel_text:
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_rel",
            section="relations",
            text=f"{label}\n\n{rel_text}",
            attack_techniques=attack_ids,
            **common_kwargs,
        )

    # -------------------------------------------------------------------------
    # 4) Attack mappings summary chunk
    # -------------------------------------------------------------------------
    if attack_ids:
        text_parts = [
            label,
            "",
            "Mapped ATT&CK Techniques:",
        ]
        
        # Add technique IDs with labels if available
        mapping_by_id = {m.technique_id: m for m in attack_mappings}
        
        for tid in attack_ids:
            mapping = mapping_by_id.get(tid)
            if mapping and mapping.technique_label:
                text_parts.append(f"- {tid}: {mapping.technique_label}")
            else:
                text_parts.append(f"- {tid}")
        
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_attack_summary",
            section="attack_mappings",
            text="\n".join(text_parts),
            attack_techniques=attack_ids,
            **common_kwargs,
        )

    # -------------------------------------------------------------------------
    # 5) Per-technique attack mapping chunks (NEW)
    # -------------------------------------------------------------------------
    # These enable precise retrieval for queries like "what defends against T1059?"
    for mapping in attack_mappings:
        mapping_text = mapping.to_text(label)
        
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_attack_{mapping.technique_id}",
            section="attack_mapping",
            text=mapping_text,
            attack_techniques=[mapping.technique_id],  # Only this technique
            primary_attack_technique=mapping.technique_id,
            **common_kwargs,
        )

    # -------------------------------------------------------------------------
    # 6) Fallback: If no chunks generated, create minimal definition chunk
    # -------------------------------------------------------------------------
    # This ensures every defense has at least one chunk
    if not definition and not kb_article and not rel_text and not attack_ids:
        fallback_text = f"{label}\n\nD3FEND ID: {d3fend_id}"
        if uri:
            fallback_text += f"\nURI: {uri}"
        
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_minimal",
            section="minimal",
            text=fallback_text,
            attack_techniques=[],
            **common_kwargs,
        )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def _compute_stats(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute statistics about generated chunks."""
    stats: Dict[str, Any] = {
        "total_chunks": len(chunks),
        "chunks_by_section": {},
        "unique_d3fend_ids": set(),
        "unique_attack_techniques": set(),
        "chunks_with_attack_mappings": 0,
        "per_technique_mapping_chunks": 0,
    }
    
    for chunk in chunks:
        section = chunk.get("section", "unknown")
        stats["chunks_by_section"][section] = stats["chunks_by_section"].get(section, 0) + 1
        
        if chunk.get("d3fend_id"):
            stats["unique_d3fend_ids"].add(chunk["d3fend_id"])
        
        attack_techs = chunk.get("attack_techniques", [])
        if attack_techs:
            stats["chunks_with_attack_mappings"] += 1
            for t in attack_techs:
                stats["unique_attack_techniques"].add(t)
        
        if section == "attack_mapping":
            stats["per_technique_mapping_chunks"] += 1
    
    # Convert sets to counts
    stats["unique_d3fend_ids"] = len(stats["unique_d3fend_ids"])
    stats["unique_attack_techniques"] = len(stats["unique_attack_techniques"])
    
    return stats


def _print_stats(stats: Dict[str, Any]) -> None:
    """Print statistics in readable format."""
    print("\n[stats] D3FEND Chunk Statistics:")
    print(f"  Total chunks: {stats['total_chunks']}")
    print(f"  Unique D3FEND defenses: {stats['unique_d3fend_ids']}")
    print(f"  Unique ATT&CK techniques mapped: {stats['unique_attack_techniques']}")
    print(f"  Chunks with ATT&CK mappings: {stats['chunks_with_attack_mappings']}")
    print(f"  Per-technique mapping chunks: {stats['per_technique_mapping_chunks']}")
    print("\n[stats] Chunks by section:")
    for section, count in sorted(stats["chunks_by_section"].items()):
        print(f"    {section}: {count}")


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_d3fend_chunks(
    input_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Build D3FEND chunks from normalized defenses JSONL.
    
    Args:
        input_path: Override input file (default: IN_JSONL)
        output_path: Override output file (default: OUT_JSONL)
        verbose: Print progress information
    
    Returns:
        Dict with build results and statistics.
    """
    in_path = input_path or IN_JSONL
    out_path = output_path or OUT_JSONL
    
    results: Dict[str, Any] = {
        "input_path": str(in_path),
        "output_path": str(out_path),
        "defenses_count": 0,
        "chunks_count": 0,
        "stats": None,
        "errors": [],
    }
    
    # Load defenses
    if verbose:
        print(f"[build] Loading D3FEND defenses from {in_path} ...")
    
    try:
        defenses = list(_load_jsonl(in_path))
    except FileNotFoundError as e:
        print(f"[error] {e}")
        results["errors"].append(str(e))
        return results
    except json.JSONDecodeError as e:
        print(f"[error] {e}")
        results["errors"].append(str(e))
        return results
    
    results["defenses_count"] = len(defenses)
    
    if verbose:
        print(f"[build] Defenses loaded: {len(defenses)}")

    # Generate chunks
    if verbose:
        print("[build] Generating chunks ...")
    
    all_chunks: List[Dict[str, Any]] = []
    chunking_errors = 0
    
    for defense in defenses:
        try:
            for chunk in iter_d3fend_chunks(defense):
                if chunk.text and chunk.text.strip():
                    all_chunks.append(chunk.to_dict())
        except Exception as e:
            chunking_errors += 1
            d3id = defense.get("d3fend_id", "unknown")
            if chunking_errors <= 5:
                print(f"[warn] Error chunking defense {d3id}: {e}")
    
    if chunking_errors > 5:
        print(f"[warn] ... and {chunking_errors - 5} more chunking errors")

    # Write chunks
    if verbose:
        print(f"[build] Writing D3FEND chunks to {out_path} ...")
    
    n_chunks = _write_jsonl(out_path, all_chunks)
    results["chunks_count"] = n_chunks

    # Compute statistics
    stats = _compute_stats(all_chunks)
    results["stats"] = stats
    
    if verbose:
        _print_stats(stats)

    # Summary
    print(f"\n[done] D3FEND chunking complete")
    print(f"  Input:    {in_path}")
    print(f"  Defenses: {len(defenses)}")
    print(f"  Chunks:   {n_chunks}")
    print(f"  Output:   {out_path}")
    
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Build D3FEND RAG chunks from normalized defenses JSONL."
    )
    parser.add_argument(
        "--input", "-i",
        type=Path,
        default=None,
        help=f"Input JSONL file (default: {IN_JSONL})",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help=f"Output JSONL file (default: {OUT_JSONL})",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Reduce output verbosity.",
    )
    
    args = parser.parse_args()
    
    results = build_d3fend_chunks(
        input_path=args.input,
        output_path=args.output,
        verbose=not args.quiet,
    )
    
    if results["errors"]:
        exit(1)


if __name__ == "__main__":
    main()
