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
from pathlib import Path
from typing import Iterable, Dict, Any, Iterator

from mitre_expert.models.technique import TechniqueRecord


# Prefer enriched techniques if available, else fallback to raw
ENRICHED_TECHNIQUES_PATH = Path("data/processed/mitre/techniques_full_enriched_v2.jsonl")
RAW_TECHNIQUES_FALLBACK_PATH = Path("data/raw/mitre/techniques_full.jsonl")

KNOWLEDGE_PACK_PATH = Path("data/processed/mitre/mitre_knowledge_pack_v1.jsonl")
CHUNKS_PATH = Path("data/processed/mitre/mitre_chunks_v1.jsonl")


def _pick_input_path() -> Path:
    """
    Prefer enriched techniques file if present, else fallback to raw.
    """
    if ENRICHED_TECHNIQUES_PATH.exists():
        return ENRICHED_TECHNIQUES_PATH
    return RAW_TECHNIQUES_FALLBACK_PATH


def _load_raw_techniques(path: Path) -> Iterator[Dict[str, Any]]:
    """
    Load raw technique records.

    Supports:
    - A single JSON object with key "techniques" that is a list of technique objects.
    - A JSON array of technique objects.
    - JSONL (one technique JSON object per line).
    """
    if not path.exists():
        raise FileNotFoundError(f"Raw techniques file not found: {path}")

    # Peek full file first to detect JSON object/array vs JSONL.
    text = path.read_text(encoding="utf-8").strip()

    # 1) Try full-file JSON (object or list)
    try:
        data = json.loads(text)

        # Case A: {"techniques": [ {...}, {...} ]}
        if isinstance(data, dict) and "techniques" in data:
            techniques = data["techniques"]
            if not isinstance(techniques, list):
                raise ValueError('"techniques" key is not a list')
            for rec in techniques:
                if isinstance(rec, dict):
                    yield rec
            return

        # Case B: [ {...}, {...} ]
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict):
                    yield rec
            return

        # If it's some other shape, fall through to JSONL mode
        print("[warn] Unsupported full-file JSON shape, falling back to JSONL parsing...")

    except json.JSONDecodeError:
        # Not a single valid JSON document -> assume JSONL
        pass

    # 2) Fallback: JSONL (one JSON object per line)
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
    """Write an iterable of dicts to JSONL. Returns count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    return count


def build_knowledge_pack() -> None:
    """
    Main builder:
    - Normalizes raw techniques into TechniqueRecord
    - Writes normalized techniques JSONL
    - Generates ChunkRecord objects per technique
    - Writes chunks JSONL
    """
    input_path = _pick_input_path()
    print(f"[build] Loading techniques from {input_path} ...")

    raw_iter = list(_load_raw_techniques(input_path))

    # 1) Normalize techniques
    print(f"[build] Normalizing {len(raw_iter)} techniques ...")

    technique_records: list[TechniqueRecord] = []
    for rec in raw_iter:
        try:
            t = TechniqueRecord.from_raw(rec)
            technique_records.append(t)
        except KeyError as e:
            # If a record is missing required fields, log and skip
            print(f"[warn] Skipping record due to missing key: {e}")
            continue

    # 2) Write normalized techniques
    print(f"[build] Writing normalized techniques to {KNOWLEDGE_PACK_PATH} ...")

    technique_dicts = (t.to_dict() for t in technique_records)
    n_techniques = _write_jsonl(KNOWLEDGE_PACK_PATH, technique_dicts)

    # 3) Generate and write chunks
    print("[build] Generating chunks for RAG ...")

    def chunk_dicts() -> Iterable[Dict[str, Any]]:
        for t in technique_records:
            for chunk in t.iter_chunks():
                if not chunk.text or not chunk.text.strip():
                    continue
                yield chunk.to_dict()

    print(f"[build] Writing chunks to {CHUNKS_PATH} ...")
    n_chunks = _write_jsonl(CHUNKS_PATH, chunk_dicts())

    print(f"[done] Techniques written: {n_techniques}")
    print(f"[done] Chunks written:     {n_chunks}")


if __name__ == "__main__":
    build_knowledge_pack()
