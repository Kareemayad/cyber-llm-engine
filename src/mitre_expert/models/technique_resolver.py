# src/mitre_expert/models/technique_resolver.py

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# repo root: .../cyber-llm-engine
REPO_ROOT = Path(__file__).resolve().parents[3]

# We derive technique metadata from the chunks file you already use for Chroma
CHUNKS_PATH = REPO_ROOT / "data" / "processed" / "mitre" / "mitre_chunks_v1.jsonl"

# Regex for MITRE technique IDs like T1548 or T1055.013
TECHID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

# Common chunk_id shapes you generate:
#   T1548_desc
#   T1548_proc_G1234
#   T1548_mit_M1047
#   T1548_det_AN0975
_CHUNKID_TECH_PREFIX_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)_", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TechniqueRecord:
    id: str
    name: str
    normalized_name: str


@dataclass(frozen=True)
class TechniqueCandidate:
    id: str
    name: str
    score: float      # 0.0 – 1.0
    source: str       # e.g. "id_regex", "name_exact", "name_fuzzy"


# Internal storage
_TECHNIQUES: Dict[str, TechniqueRecord] = {}
# normalized_name -> set(ids) (in case of name reuse)
_NAME_INDEX: Dict[str, set[str]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_text(s: str) -> str:
    """
    Simple normalization:
        - lowercase
        - replace non-alnum with spaces
        - collapse whitespace
    """
    s = s.lower()
    s = "".join(ch if ch.isalnum() else " " for ch in s)
    return " ".join(s.split())


def _infer_technique_id_from_record(rec: Dict[str, object]) -> Optional[str]:
    """
    Best-effort inference of technique_id when fields are missing.

    Supports:
      - chunk_id like "T1548_desc"
      - chunk_id with a technique id prefix
    """
    chunk_id = rec.get("chunk_id")
    if isinstance(chunk_id, str) and chunk_id:
        m = _CHUNKID_TECH_PREFIX_RE.match(chunk_id)
        if m:
            return m.group(1).upper()

    # As a last resort, scan any string-ish fields for an ID.
    # (Keeps resolver resilient to future format changes.)
    for key in ("technique_id", "id", "chunk_id", "technique_name", "name", "text"):
        v = rec.get(key)
        if isinstance(v, str) and v:
            m = TECHID_RE.search(v)
            if m:
                return m.group(1).upper()

    return None


def _add_technique(tech_id: str, name: Optional[str]) -> None:
    if not tech_id:
        return

    tech_id = tech_id.upper()
    name = (name or "").strip()
    normalized = _normalize_text(name) if name else ""

    # If we already have this technique, keep the first non-empty name.
    if tech_id in _TECHNIQUES:
        existing = _TECHNIQUES[tech_id]
        if existing.name:
            return

    rec = TechniqueRecord(id=tech_id, name=name, normalized_name=normalized)
    _TECHNIQUES[tech_id] = rec

    if normalized:
        _NAME_INDEX.setdefault(normalized, set()).add(tech_id)


def _load_techniques_from_chunks() -> None:
    """
    Build technique ID -> name mapping by scanning mitre_chunks_v1.jsonl.

    Your current chunk format is FLAT (no nested 'metadata'), but we keep
    backward compatibility with older records that might include 'metadata'.
    """
    if not CHUNKS_PATH.exists():
        print(
            f"[resolver] WARNING: chunks file not found at {CHUNKS_PATH}, "
            f"technique resolver will have empty index."
        )
        return

    count_lines = 0
    count_techs_before = len(_TECHNIQUES)

    print(f"[resolver] Loading techniques from {CHUNKS_PATH} ...")

    with CHUNKS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count_lines += 1

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            meta = rec.get("metadata", {}) or {}
            if not isinstance(meta, dict):
                meta = {}

            # Prefer explicit technique_id fields; avoid using rec["id"] because
            # that is often a chunk id, not a technique id.
            tech_id = (
                meta.get("technique_id")
                or rec.get("technique_id")
                or _infer_technique_id_from_record(rec)
            )

            tech_name = (
                meta.get("technique_name")
                or meta.get("name")
                or rec.get("technique_name")
                or rec.get("name")
            )

            if not tech_id:
                continue

            _add_technique(str(tech_id), str(tech_name) if tech_name is not None else None)

    print(
        f"[resolver] Parsed {count_lines} chunk records; "
        f"techniques before={count_techs_before}, after={len(_TECHNIQUES)}"
    )


# Try to use rapidfuzz if available for better fuzzy matching.
try:
    from rapidfuzz import fuzz as _rfuzz  # type: ignore[import]

    _HAVE_RAPIDFUZZ = True
except Exception:
    _HAVE_RAPIDFUZZ = False


def _fuzzy_score(name: str, text: str) -> float:
    """
    Return a 0-1 fuzzy score between technique name and query text.
    Uses rapidfuzz if available, else a simple containment fallback.
    """
    name_l = name.lower()
    text_l = text.lower()

    if not name_l or not text_l:
        return 0.0

    if _HAVE_RAPIDFUZZ:
        score = _rfuzz.partial_ratio(name_l, text_l)
        return float(score) / 100.0

    if name_l in text_l:
        return 0.8
    return 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_all_techniques() -> List[TechniqueRecord]:
    """Return all known techniques."""
    return list(_TECHNIQUES.values())


def resolve_techniques_from_text(
    text: str,
    max_results: int = 5,
) -> List[TechniqueCandidate]:
    """
    Deterministically resolve technique candidates from text using:
      1) Explicit IDs (T#### / T####.###) via regex
      2) Exact name match (normalized substring)
      3) Fuzzy name match (rapidfuzz / fallback)

    Returns a list of TechniqueCandidate sorted by score desc.
    """
    if not text:
        return []

    # Lazy safety: if imported before chunks exist, allow runtime call to work
    if not _TECHNIQUES:
        return []

    text_norm = _normalize_text(text)
    text_lower = text.lower()

    candidates: Dict[str, TechniqueCandidate] = {}

    def _update_candidate(tid: str, name: str, score: float, source: str) -> None:
        existing = candidates.get(tid)
        if existing is None or score > existing.score:
            candidates[tid] = TechniqueCandidate(
                id=tid,
                name=name,
                score=score,
                source=source,
            )

    # 1) Explicit technique IDs in text, e.g. (T1548), T1055.013, etc.
    for match in TECHID_RE.finditer(text):
        tid = match.group(1).upper()
        rec = _TECHNIQUES.get(tid)
        _update_candidate(tid, rec.name if rec else "", 1.0, "id_regex")

    # 2) Exact name match (normalized_name is substring of normalized text)
    for rec in _TECHNIQUES.values():
        if not rec.normalized_name:
            continue
        if rec.normalized_name in text_norm:
            _update_candidate(rec.id, rec.name, 0.95, "name_exact")

    # 3) Fuzzy name match
    for rec in _TECHNIQUES.values():
        if not rec.name:
            continue
        existing = candidates.get(rec.id)
        if existing and existing.score >= 0.9:
            continue

        score = _fuzzy_score(rec.name, text_lower)
        if score >= 0.75:
            _update_candidate(rec.id, rec.name, score, "name_fuzzy")

    sorted_cands = sorted(candidates.values(), key=lambda c: c.score, reverse=True)
    return sorted_cands[:max_results]


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

_load_techniques_from_chunks()
print(f"[resolver] Technique resolver ready with {len(_TECHNIQUES)} techniques.")
