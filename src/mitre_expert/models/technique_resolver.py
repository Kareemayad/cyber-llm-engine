from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_CHUNKS_PATH = REPO_ROOT / "data" / "processed" / "mitre" / "mitre_chunks_v1.jsonl"
CHUNKS_PATH = Path(os.getenv("MITRE_RESOLVER_CHUNKS_PATH", str(DEFAULT_CHUNKS_PATH)))

TECHID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
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


_TECHNIQUES: Dict[str, TechniqueRecord] = {}
_NAME_INDEX: Dict[str, set[str]] = {}

# Track load state so we can retry if file was missing previously
_LOADED_ONCE = False
_LAST_LOADED_PATH: Optional[Path] = None
_LAST_LOADED_MTIME_NS: Optional[int] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_text(s: str) -> str:
    s = s.lower()
    s = "".join(ch if ch.isalnum() else " " for ch in s)
    return " ".join(s.split())


def _infer_technique_id_from_record(rec: Dict[str, object]) -> Optional[str]:
    chunk_id = rec.get("chunk_id")
    if isinstance(chunk_id, str) and chunk_id:
        m = _CHUNKID_TECH_PREFIX_RE.match(chunk_id)
        if m:
            return m.group(1).upper()

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

    if tech_id in _TECHNIQUES:
        existing = _TECHNIQUES[tech_id]
        if existing.name:
            return

    rec = TechniqueRecord(id=tech_id, name=name, normalized_name=normalized)
    _TECHNIQUES[tech_id] = rec

    if normalized:
        _NAME_INDEX.setdefault(normalized, set()).add(tech_id)


def _clear_index() -> None:
    _TECHNIQUES.clear()
    _NAME_INDEX.clear()


def _load_techniques_from_chunks(path: Path) -> None:
    """
    Build technique ID -> name mapping by scanning mitre_chunks_v1.jsonl.
    Supports both flat records and legacy {metadata:{...}}.
    """
    count_lines = 0
    count_techs_before = len(_TECHNIQUES)

    print(f"[resolver] Loading techniques from {path} ...")

    with path.open("r", encoding="utf-8") as f:
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


def _chunks_signature(path: Path) -> Optional[int]:
    """Return mtime_ns for change detection, else None if missing."""
    try:
        return path.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def ensure_loaded(force: bool = False) -> None:
    """
    Lazy-load index. If chunks were missing earlier, we can retry later.
    Also reload automatically if the chunks file changed on disk.
    """
    global _LOADED_ONCE, _LAST_LOADED_PATH, _LAST_LOADED_MTIME_NS

    mtime_ns = _chunks_signature(CHUNKS_PATH)

    if not force:
        # Already loaded and file hasn't changed
        if _LOADED_ONCE and mtime_ns is not None and mtime_ns == _LAST_LOADED_MTIME_NS:
            return
        # If we've loaded once but file missing now, keep current index
        if _LOADED_ONCE and mtime_ns is None:
            return

    if mtime_ns is None:
        # Don't “poison” the index forever — just warn and return.
        print(
            f"[resolver] WARNING: chunks file not found at {CHUNKS_PATH}. "
            "Technique resolver will remain empty until the file exists."
        )
        _LOADED_ONCE = True
        _LAST_LOADED_PATH = CHUNKS_PATH
        _LAST_LOADED_MTIME_NS = None
        return

    # Reload from scratch
    _clear_index()
    _load_techniques_from_chunks(CHUNKS_PATH)

    _LOADED_ONCE = True
    _LAST_LOADED_PATH = CHUNKS_PATH
    _LAST_LOADED_MTIME_NS = mtime_ns

    print(f"[resolver] Technique resolver ready with {len(_TECHNIQUES)} techniques.")


# rapidfuzz optional
try:
    from rapidfuzz import fuzz as _rfuzz  # type: ignore[import]
    _HAVE_RAPIDFUZZ = True
except Exception:
    _HAVE_RAPIDFUZZ = False


def _fuzzy_score(name: str, text: str) -> float:
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
    ensure_loaded()
    return list(_TECHNIQUES.values())


def resolve_techniques_from_text(text: str, max_results: int = 5) -> List[TechniqueCandidate]:
    ensure_loaded()

    if not text or not _TECHNIQUES:
        return []

    text_norm = _normalize_text(text)
    text_lower = text.lower()

    candidates: Dict[str, TechniqueCandidate] = {}

    def _update_candidate(tid: str, name: str, score: float, source: str) -> None:
        existing = candidates.get(tid)
        if existing is None or score > existing.score:
            candidates[tid] = TechniqueCandidate(id=tid, name=name, score=score, source=source)

    # 1) Explicit IDs
    for match in TECHID_RE.finditer(text):
        tid = match.group(1).upper()
        rec = _TECHNIQUES.get(tid)
        _update_candidate(tid, rec.name if rec else "", 1.0, "id_regex")

    # 2) Exact name match (normalized substring)
    for rec in _TECHNIQUES.values():
        if rec.normalized_name and rec.normalized_name in text_norm:
            _update_candidate(rec.id, rec.name, 0.95, "name_exact")

    # 3) Fuzzy match
    for rec in _TECHNIQUES.values():
        if not rec.name:
            continue
        existing = candidates.get(rec.id)
        if existing and existing.score >= 0.9:
            continue

        score = _fuzzy_score(rec.name, text_lower)
        if score >= 0.75:
            _update_candidate(rec.id, rec.name, score, "name_fuzzy")

    return sorted(candidates.values(), key=lambda c: c.score, reverse=True)[:max_results]
