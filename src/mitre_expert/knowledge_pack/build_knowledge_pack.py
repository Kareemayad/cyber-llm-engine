# src/mitre_expert/knowledge_pack/build_knowledge_pack.py
"""
Build the MITRE knowledge pack and RAG chunks from raw techniques data.

Supported input formats:

1) Single JSON object with "techniques" array:
   {
     "techniques": [ { ..technique.. }, { ..technique.. }, ... ]
   }

2) JSON array of technique objects:
   [
     { ..technique.. },
     { ..technique.. }
   ]

3) JSONL: one technique JSON object per line.

Outputs:
    data/processed/mitre/mitre_knowledge_pack_v1.jsonl   # normalized techniques
    data/processed/mitre/mitre_chunks_v1.jsonl           # exploded chunks for RAG
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Dict, Any, Iterator, List, Optional

from mitre_expert.models.technique import TechniqueRecord

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ENRICHED_DIR = Path("data/processed/mitre")
RAW_TECHNIQUES_FALLBACK_PATH = Path("data/raw/mitre/techniques_full.jsonl")

KNOWLEDGE_PACK_PATH = Path("data/processed/mitre/mitre_knowledge_pack_v1.jsonl")
CHUNKS_PATH = Path("data/processed/mitre/mitre_chunks_v1.jsonl")

# Canonical enriched filename (no version suffix)
CANONICAL_ENRICHED_FILENAME = "techniques_full_enriched.jsonl"

# Legacy pattern: techniques_full_enriched_vN.jsonl
_ENRICHED_VERSION_RE = re.compile(r"^techniques_full_enriched_v(\d+)\.jsonl$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Input file selection
# ---------------------------------------------------------------------------

def _find_latest_versioned_enriched_file() -> Optional[Path]:
    """
    Find the highest-version techniques_full_enriched_vN.jsonl in ENRICHED_DIR.
    Returns None if no such file exists.
    
    This is a legacy fallback for older versioned files.
    """
    if not ENRICHED_DIR.exists():
        return None

    best_ver = -1
    best_path: Optional[Path] = None

    for p in ENRICHED_DIR.iterdir():
        if not p.is_file():
            continue
        m = _ENRICHED_VERSION_RE.match(p.name)
        if not m:
            continue
        try:
            ver = int(m.group(1))
        except Exception:
            continue
        if ver > best_ver:
            best_ver = ver
            best_path = p

    return best_path


def _pick_input_path() -> Path:
    """
    Select the best available input file for techniques.
    
    Priority order:
    1. Canonical enriched file (techniques_full_enriched.jsonl) - preferred
    2. Latest versioned enriched file (techniques_full_enriched_vN.jsonl) - legacy
    3. Raw techniques file (techniques_full.jsonl) - fallback
    
    Returns:
        Path to the selected input file.
    
    Raises:
        FileNotFoundError: If no suitable input file is found.
    """
    # 1. Canonical enriched file (no version suffix)
    canonical_path = ENRICHED_DIR / CANONICAL_ENRICHED_FILENAME
    if canonical_path.exists():
        print(f"[build] Using canonical enriched file: {canonical_path}")
        return canonical_path

    # 2. Latest versioned enriched file (legacy support)
    latest_versioned = _find_latest_versioned_enriched_file()
    if latest_versioned is not None and latest_versioned.exists():
        print(f"[build] Using versioned enriched file: {latest_versioned}")
        print(f"[build] ⚠️  Consider running: python scripts/consolidate_versions.py")
        return latest_versioned

    # 3. Raw techniques fallback
    if RAW_TECHNIQUES_FALLBACK_PATH.exists():
        print(f"[build] Using raw techniques (not enriched): {RAW_TECHNIQUES_FALLBACK_PATH}")
        print(f"[build] ⚠️  Detection telemetry will be missing. Run enrichment pipeline first.")
        return RAW_TECHNIQUES_FALLBACK_PATH

    # No suitable file found
    raise FileNotFoundError(
        f"No techniques file found. Searched:\n"
        f"  1. {canonical_path}\n"
        f"  2. {ENRICHED_DIR}/techniques_full_enriched_vN.jsonl\n"
        f"  3. {RAW_TECHNIQUES_FALLBACK_PATH}\n"
        f"Please run the enrichment pipeline or provide raw techniques."
    )


# ---------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------

def _load_raw_techniques(path: Path) -> Iterator[Dict[str, Any]]:
    """
    Load raw technique records from various formats.

    Supports:
    - A single JSON object with key "techniques" that is a list of technique objects.
    - A JSON array of technique objects.
    - JSONL (one technique JSON object per line).
    
    Yields:
        Dict[str, Any]: Individual technique records.
    """
    if not path.exists():
        raise FileNotFoundError(f"Techniques file not found: {path}")

    # Peek full file first to detect JSON object/array vs JSONL
    text = path.read_text(encoding="utf-8").strip()
    
    if not text:
        print(f"[warn] Empty techniques file: {path}")
        return

    # 1) Try full-file JSON (object or list)
    try:
        data = json.loads(text)

        # Case A: {"techniques": [ {...}, {...} ]}
        if isinstance(data, dict) and "techniques" in data:
            techniques = data["techniques"]
            if not isinstance(techniques, list):
                raise ValueError('"techniques" key is not a list')
            count = 0
            for rec in techniques:
                if isinstance(rec, dict):
                    yield rec
                    count += 1
            print(f"[build] Loaded {count} techniques from JSON object with 'techniques' key")
            return

        # Case B: [ {...}, {...} ]
        if isinstance(data, list):
            count = 0
            for rec in data:
                if isinstance(rec, dict):
                    yield rec
                    count += 1
            print(f"[build] Loaded {count} techniques from JSON array")
            return

        # If it's some other shape, fall through to JSONL mode
        print("[warn] Unsupported full-file JSON shape, falling back to JSONL parsing...")

    except json.JSONDecodeError:
        # Not a single valid JSON document -> assume JSONL
        pass

    # 2) Fallback: JSONL (one JSON object per line)
    count = 0
    bad_lines = 0
    
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                bad_lines += 1
                if bad_lines <= 5:
                    print(f"[warn] Skipping malformed JSONL line {i}: {e.msg}")
                continue
            
            if isinstance(obj, dict):
                yield obj
                count += 1

    if bad_lines > 5:
        print(f"[warn] ... and {bad_lines - 5} more malformed lines")
    
    print(f"[build] Loaded {count} techniques from JSONL")


# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------

def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    """
    Write an iterable of dicts to JSONL format.
    
    Args:
        path: Output file path.
        records: Iterable of dictionaries to write.
    
    Returns:
        int: Number of records written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    return count


# ---------------------------------------------------------------------------
# Statistics and validation
# ---------------------------------------------------------------------------

def _compute_chunk_stats(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute statistics about generated chunks."""
    stats: Dict[str, Any] = {
        "total_chunks": len(chunks),
        "chunks_by_section": {},
        "chunks_with_telemetry": 0,
        "unique_techniques": set(),
        "unique_mitigations": set(),
        "unique_analytics": set(),
    }
    
    for chunk in chunks:
        # Count by section
        section = chunk.get("section", "unknown")
        stats["chunks_by_section"][section] = stats["chunks_by_section"].get(section, 0) + 1
        
        # Track unique IDs
        if chunk.get("technique_id"):
            stats["unique_techniques"].add(chunk["technique_id"])
        if chunk.get("mitigation_id"):
            stats["unique_mitigations"].add(chunk["mitigation_id"])
        if chunk.get("analytic_id") or chunk.get("analytic_stix_id"):
            aid = chunk.get("analytic_id") or chunk.get("analytic_stix_id")
            stats["unique_analytics"].add(aid)
        
        # Check for telemetry
        if chunk.get("log_source_names") or chunk.get("data_component_ids"):
            stats["chunks_with_telemetry"] += 1
    
    # Convert sets to counts for JSON serialization
    stats["unique_techniques"] = len(stats["unique_techniques"])
    stats["unique_mitigations"] = len(stats["unique_mitigations"])
    stats["unique_analytics"] = len(stats["unique_analytics"])
    
    return stats


def _print_stats(stats: Dict[str, Any]) -> None:
    """Print chunk statistics in a readable format."""
    print("\n[stats] Chunk Statistics:")
    print(f"  Total chunks: {stats['total_chunks']}")
    print(f"  Unique techniques: {stats['unique_techniques']}")
    print(f"  Unique mitigations: {stats['unique_mitigations']}")
    print(f"  Unique analytics: {stats['unique_analytics']}")
    print(f"  Chunks with telemetry: {stats['chunks_with_telemetry']}")
    print("\n[stats] Chunks by section:")
    for section, count in sorted(stats["chunks_by_section"].items()):
        print(f"    {section}: {count}")


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_knowledge_pack(
    verbose: bool = True,
    validate: bool = True,
) -> Dict[str, Any]:
    """
    Main builder function.
    
    Steps:
    1. Select and load the best available techniques file
    2. Normalize techniques into TechniqueRecord objects
    3. Write normalized techniques JSONL (knowledge pack)
    4. Generate ChunkRecord objects per technique
    5. Write chunks JSONL (for RAG indexing)
    
    Args:
        verbose: If True, print detailed progress information.
        validate: If True, compute and print chunk statistics.
    
    Returns:
        Dict with build results and statistics.
    """
    results: Dict[str, Any] = {
        "input_path": None,
        "techniques_count": 0,
        "chunks_count": 0,
        "errors": [],
        "warnings": [],
        "stats": None,
    }
    
    # 1. Select input file
    try:
        input_path = _pick_input_path()
        results["input_path"] = str(input_path)
    except FileNotFoundError as e:
        print(f"[error] {e}")
        results["errors"].append(str(e))
        return results

    # 2. Load raw techniques
    if verbose:
        print(f"\n[build] Loading techniques from {input_path} ...")
    
    raw_techniques = list(_load_raw_techniques(input_path))
    
    if not raw_techniques:
        msg = "No techniques loaded from input file"
        print(f"[error] {msg}")
        results["errors"].append(msg)
        return results

    # 3. Normalize techniques
    if verbose:
        print(f"[build] Normalizing {len(raw_techniques)} techniques ...")

    technique_records: List[TechniqueRecord] = []
    normalization_errors = 0
    
    for i, rec in enumerate(raw_techniques):
        try:
            t = TechniqueRecord.from_raw(rec)
            technique_records.append(t)
        except KeyError as e:
            normalization_errors += 1
            if normalization_errors <= 5:
                tid = rec.get("technique_id", rec.get("id", f"index_{i}"))
                print(f"[warn] Skipping technique {tid} due to missing key: {e}")
        except Exception as e:
            normalization_errors += 1
            if normalization_errors <= 5:
                tid = rec.get("technique_id", rec.get("id", f"index_{i}"))
                print(f"[warn] Skipping technique {tid} due to error: {e}")

    if normalization_errors > 5:
        print(f"[warn] ... and {normalization_errors - 5} more normalization errors")
    
    if normalization_errors > 0:
        results["warnings"].append(f"{normalization_errors} techniques failed normalization")

    if not technique_records:
        msg = "No techniques successfully normalized"
        print(f"[error] {msg}")
        results["errors"].append(msg)
        return results

    # 4. Write normalized techniques (knowledge pack)
    if verbose:
        print(f"[build] Writing normalized techniques to {KNOWLEDGE_PACK_PATH} ...")
    
    technique_dicts = (t.to_dict() for t in technique_records)
    n_techniques = _write_jsonl(KNOWLEDGE_PACK_PATH, technique_dicts)
    results["techniques_count"] = n_techniques

    # 5. Generate chunks
    if verbose:
        print("[build] Generating chunks for RAG ...")

    all_chunks: List[Dict[str, Any]] = []
    chunking_errors = 0
    
    for t in technique_records:
        try:
            for chunk in t.iter_chunks():
                if chunk.text and chunk.text.strip():
                    all_chunks.append(chunk.to_dict())
        except Exception as e:
            chunking_errors += 1
            if chunking_errors <= 5:
                print(f"[warn] Error chunking technique {t.technique_id}: {e}")

    if chunking_errors > 5:
        print(f"[warn] ... and {chunking_errors - 5} more chunking errors")
    
    if chunking_errors > 0:
        results["warnings"].append(f"{chunking_errors} techniques failed chunking")

    # 6. Write chunks
    if verbose:
        print(f"[build] Writing chunks to {CHUNKS_PATH} ...")
    
    n_chunks = _write_jsonl(CHUNKS_PATH, all_chunks)
    results["chunks_count"] = n_chunks

    # 7. Compute and print statistics
    if validate:
        stats = _compute_chunk_stats(all_chunks)
        results["stats"] = stats
        if verbose:
            _print_stats(stats)

    # 8. Summary
    print(f"\n[done] Knowledge pack build complete")
    print(f"  Input:      {input_path}")
    print(f"  Techniques: {n_techniques}")
    print(f"  Chunks:     {n_chunks}")
    print(f"  Output:")
    print(f"    - {KNOWLEDGE_PACK_PATH}")
    print(f"    - {CHUNKS_PATH}")
    
    if results["warnings"]:
        print(f"\n[warn] Warnings: {len(results['warnings'])}")
        for w in results["warnings"]:
            print(f"  - {w}")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Build MITRE knowledge pack and RAG chunks from techniques data."
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Reduce output verbosity.",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip chunk validation and statistics.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Override input file path (default: auto-detect).",
    )
    
    args = parser.parse_args()
    
    # Handle input override
    if args.input:
        global ENRICHED_DIR, RAW_TECHNIQUES_FALLBACK_PATH
        if args.input.exists():
            # Temporarily override the path selection
            print(f"[build] Using specified input: {args.input}")
            # We need to modify _pick_input_path behavior or just load directly
            # For simplicity, we'll create a wrapper
            raw_techniques = list(_load_raw_techniques(args.input))
            # ... rest would need refactoring to support this cleanly
            print("[warn] --input override not fully implemented, using auto-detect")
    
    results = build_knowledge_pack(
        verbose=not args.quiet,
        validate=not args.no_validate,
    )
    
    # Exit with error code if there were errors
    if results["errors"]:
        exit(1)


if __name__ == "__main__":
    main()