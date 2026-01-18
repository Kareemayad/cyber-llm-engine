"""
Deterministic technique resolver for MITRE ATT&CK.

Extracts technique IDs from text using:
1. Regex pattern matching (T1234, T1234.001)
2. Exact name matching (normalized)
3. Fuzzy name matching (optional rapidfuzz)
4. Alias/synonym matching

Used by mitre_mapper.py as first-pass extraction before semantic boosting.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from mitre_expert.config import (
    MITRE_KNOWLEDGE_PACK_PATH,
    MITRE_CHUNKS_PATH,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

KNOWLEDGE_PACK_PATH = MITRE_KNOWLEDGE_PACK_PATH
CHUNKS_PATH = MITRE_CHUNKS_PATH

# Regex patterns
TECHID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_CHUNKID_TECH_PREFIX_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)_", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Common technique aliases (manual curation for high-value mappings)
# ---------------------------------------------------------------------------

# Maps common terms/aliases to technique IDs
# These are terms that appear frequently in logs/alerts but don't contain the technique name
TECHNIQUE_ALIASES: Dict[str, List[str]] = {
    # Credential Access
    "credential dumping": ["T1003"],
    "lsass": ["T1003.001"],
    "mimikatz": ["T1003.001", "T1558.003"],
    "pass the hash": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "kerberoasting": ["T1558.003"],
    "golden ticket": ["T1558.001"],
    "silver ticket": ["T1558.002"],
    "dcsync": ["T1003.006"],
    "ntds.dit": ["T1003.003"],
    "sam database": ["T1003.002"],
    "cached credentials": ["T1003.005"],
    
    # Execution
    "powershell": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "command prompt": ["T1059.003"],
    "wmi": ["T1047"],
    "wmic": ["T1047"],
    "mshta": ["T1218.005"],
    "rundll32": ["T1218.011"],
    "regsvr32": ["T1218.010"],
    "certutil": ["T1140", "T1105"],
    "bitsadmin": ["T1197", "T1105"],
    "msiexec": ["T1218.007"],
    "cscript": ["T1059.005"],
    "wscript": ["T1059.005"],
    
    # Persistence
    "scheduled task": ["T1053.005"],
    "schtasks": ["T1053.005"],
    "registry run key": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "service creation": ["T1543.003"],
    "new service": ["T1543.003"],
    "dll hijacking": ["T1574.001"],
    "dll side-loading": ["T1574.002"],
    
    # Defense Evasion
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "process hollowing": ["T1055.012"],
    "uac bypass": ["T1548.002"],
    "timestomp": ["T1070.006"],
    "log clearing": ["T1070.001"],
    "clear event log": ["T1070.001"],
    "obfuscation": ["T1027"],
    "encoded command": ["T1027", "T1059.001"],
    "base64": ["T1027", "T1059.001"],
    
    # Discovery
    "whoami": ["T1033"],
    "net user": ["T1087.001"],
    "net group": ["T1087.002"],
    "net localgroup": ["T1087.001"],
    "systeminfo": ["T1082"],
    "ipconfig": ["T1016"],
    "arp -a": ["T1016"],
    "netstat": ["T1049"],
    "tasklist": ["T1057"],
    "process list": ["T1057"],
    "nltest": ["T1482"],
    "domain trust": ["T1482"],
    
    # Lateral Movement
    "psexec": ["T1569.002", "T1021.002"],
    "wmiexec": ["T1047"],
    "smbexec": ["T1021.002"],
    "remote desktop": ["T1021.001"],
    "rdp": ["T1021.001"],
    "winrm": ["T1021.006"],
    "ssh": ["T1021.004"],
    "remote service": ["T1021"],
    
    # Collection
    "keylogger": ["T1056.001"],
    "screen capture": ["T1113"],
    "clipboard": ["T1115"],
    
    # Exfiltration
    "data exfiltration": ["T1041"],
    "c2": ["T1071"],
    "command and control": ["T1071"],
    "dns tunneling": ["T1071.004"],
    "http beacon": ["T1071.001"],
    
    # Impact
    "ransomware": ["T1486"],
    "encryption": ["T1486"],
    "data destruction": ["T1485"],
    "wiper": ["T1485"],
    "defacement": ["T1491"],
}

# Normalize aliases for lookup
_ALIAS_INDEX: Dict[str, List[str]] = {}


def _build_alias_index() -> None:
    """Build normalized alias lookup index."""
    _ALIAS_INDEX.clear()
    for alias, tech_ids in TECHNIQUE_ALIASES.items():
        normalized = _normalize_text(alias)
        if normalized:
            _ALIAS_INDEX[normalized] = tech_ids


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TechniqueRecord:
    """Cached technique metadata."""
    id: str
    name: str
    normalized_name: str
    parent_id: Optional[str] = None  # For sub-techniques


@dataclass(frozen=True)
class TechniqueCandidate:
    """A candidate technique match with confidence score."""
    id: str
    name: str
    score: float      # 0.0 – 1.0
    source: str       # e.g. "id_regex", "name_exact", "name_fuzzy", "alias"


# Global indexes
_TECHNIQUES: Dict[str, TechniqueRecord] = {}
_NAME_INDEX: Dict[str, Set[str]] = {}  # normalized_name -> set of technique IDs
_PARENT_INDEX: Dict[str, Set[str]] = {}  # parent_id -> set of sub-technique IDs

# Load state tracking
_LOADED_ONCE = False
_LAST_LOADED_SIGNATURE: Optional[Tuple[Optional[int], Optional[int]]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_text(s: str) -> str:
    """Normalize text for matching: lowercase, alphanumeric only, single spaces."""
    s = s.lower()
    s = "".join(ch if ch.isalnum() else " " for ch in s)
    return " ".join(s.split())


def _extract_parent_id(tech_id: str) -> Optional[str]:
    """Extract parent technique ID from sub-technique ID."""
    if "." in tech_id:
        return tech_id.split(".")[0]
    return None


def _add_technique(tech_id: str, name: Optional[str]) -> None:
    """Add a technique to the index."""
    if not tech_id:
        return

    tech_id = tech_id.upper()
    name = (name or "").strip()
    normalized = _normalize_text(name) if name else ""
    parent_id = _extract_parent_id(tech_id)

    if tech_id in _TECHNIQUES:
        existing = _TECHNIQUES[tech_id]
        # Keep first non-empty name
        if existing.name:
            return

    rec = TechniqueRecord(
        id=tech_id,
        name=name,
        normalized_name=normalized,
        parent_id=parent_id,
    )
    _TECHNIQUES[tech_id] = rec

    # Name index
    if normalized:
        _NAME_INDEX.setdefault(normalized, set()).add(tech_id)

    # Parent index (for sub-technique lookup)
    if parent_id:
        _PARENT_INDEX.setdefault(parent_id, set()).add(tech_id)


def _clear_index() -> None:
    """Clear all indexes."""
    _TECHNIQUES.clear()
    _NAME_INDEX.clear()
    _PARENT_INDEX.clear()


def _mtime_ns(path: Path) -> Optional[int]:
    """Get file modification time in nanoseconds, or None if not found."""
    try:
        return path.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def _infer_technique_id_from_chunk_record(rec: dict) -> Optional[str]:
    """
    Infer technique ID from a chunk record.
    
    Strategy:
    1. chunk_id prefix "Txxxx_" (most reliable)
    2. Check specific short fields (avoid scanning narrative text)
    """
    # Check chunk_id prefix
    chunk_id = rec.get("chunk_id")
    if isinstance(chunk_id, str) and chunk_id:
        m = _CHUNKID_TECH_PREFIX_RE.match(chunk_id)
        if m:
            return m.group(1).upper()

    # Check specific metadata fields only
    for key in ("technique_id", "id"):
        v = rec.get(key)
        if isinstance(v, str) and v:
            m = TECHID_RE.search(v)
            if m:
                return m.group(1).upper()

    return None


# ---------------------------------------------------------------------------
# Loading functions
# ---------------------------------------------------------------------------

def _load_techniques_from_knowledge_pack(path: Path) -> None:
    """
    Load technique ID -> name from mitre_knowledge_pack_v1.jsonl.
    This is the canonical source (cleaner than chunks).
    """
    count_lines = 0
    before = len(_TECHNIQUES)

    print(f"[resolver] Loading techniques from knowledge pack: {path} ...")

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

            tech_id = rec.get("technique_id")
            tech_name = rec.get("technique_name")

            if isinstance(tech_id, str) and tech_id:
                _add_technique(tech_id, str(tech_name) if tech_name is not None else None)

    print(f"[resolver] Parsed {count_lines} technique records; before={before}, after={len(_TECHNIQUES)}")


def _load_techniques_from_chunks(path: Path) -> None:
    """
    Fallback: build technique ID -> name mapping by scanning mitre_chunks_v1.jsonl.
    """
    count_lines = 0
    before = len(_TECHNIQUES)

    print(f"[resolver] Loading techniques from chunks: {path} ...")

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
                rec.get("technique_id")
                or meta.get("technique_id")
                or _infer_technique_id_from_chunk_record(rec)
            )

            tech_name = (
                rec.get("technique_name")
                or meta.get("technique_name")
                or rec.get("name")
                or meta.get("name")
            )

            if isinstance(tech_id, str) and tech_id:
                _add_technique(tech_id, str(tech_name) if tech_name is not None else None)

    print(f"[resolver] Parsed {count_lines} chunk records; before={before}, after={len(_TECHNIQUES)}")


def ensure_loaded(force: bool = False) -> None:
    """
    Lazy-load index.
    
    Preference order:
      1) knowledge pack (mitre_knowledge_pack_v1.jsonl)
      2) chunks (mitre_chunks_v1.jsonl)
      
    Auto-reloads if source files change.
    """
    global _LOADED_ONCE, _LAST_LOADED_SIGNATURE

    kp_m = _mtime_ns(KNOWLEDGE_PACK_PATH)
    ch_m = _mtime_ns(CHUNKS_PATH)
    signature = (kp_m, ch_m)

    if not force and _LOADED_ONCE and _LAST_LOADED_SIGNATURE == signature and _TECHNIQUES:
        return

    # If neither exists, warn and keep current in-memory index
    if kp_m is None and ch_m is None:
        print(
            f"[resolver] WARNING: resolver sources not found:\n"
            f"  - knowledge pack: {KNOWLEDGE_PACK_PATH}\n"
            f"  - chunks:         {CHUNKS_PATH}\n"
            "Technique resolver will remain empty until one exists."
        )
        _LOADED_ONCE = True
        _LAST_LOADED_SIGNATURE = signature
        return

    _clear_index()

    if kp_m is not None:
        _load_techniques_from_knowledge_pack(KNOWLEDGE_PACK_PATH)
    elif ch_m is not None:
        _load_techniques_from_chunks(CHUNKS_PATH)

    # Build alias index
    _build_alias_index()

    _LOADED_ONCE = True
    _LAST_LOADED_SIGNATURE = signature
    
    # Summary
    sub_technique_count = sum(1 for t in _TECHNIQUES.values() if t.parent_id)
    print(
        f"[resolver] Technique resolver ready: "
        f"{len(_TECHNIQUES)} techniques ({sub_technique_count} sub-techniques), "
        f"{len(_ALIAS_INDEX)} aliases"
    )


# ---------------------------------------------------------------------------
# Fuzzy matching (optional rapidfuzz)
# ---------------------------------------------------------------------------

try:
    from rapidfuzz import fuzz as _rfuzz  # type: ignore[import]
    _HAVE_RAPIDFUZZ = True
except ImportError:
    _HAVE_RAPIDFUZZ = False


def _fuzzy_score(name: str, text: str) -> float:
    """
    Compute fuzzy match score between technique name and text.
    Returns 0.0 - 1.0.
    """
    name_l = name.lower()
    text_l = text.lower()

    if not name_l or not text_l:
        return 0.0

    if _HAVE_RAPIDFUZZ:
        # partial_ratio handles substring matching well
        score = _rfuzz.partial_ratio(name_l, text_l)
        return float(score) / 100.0

    # Fallback: simple substring check
    if name_l in text_l:
        return 0.8
    
    # Check word overlap
    name_words = set(name_l.split())
    text_words = set(text_l.split())
    if name_words and text_words:
        overlap = len(name_words & text_words) / len(name_words)
        if overlap >= 0.5:
            return 0.6 * overlap
    
    return 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_all_techniques() -> List[TechniqueRecord]:
    """Get all loaded techniques."""
    ensure_loaded()
    return list(_TECHNIQUES.values())


def get_technique(tech_id: str) -> Optional[TechniqueRecord]:
    """Get a specific technique by ID."""
    ensure_loaded()
    return _TECHNIQUES.get(tech_id.upper())


def get_sub_techniques(parent_id: str) -> List[TechniqueRecord]:
    """Get all sub-techniques for a parent technique ID."""
    ensure_loaded()
    parent_id = parent_id.upper()
    sub_ids = _PARENT_INDEX.get(parent_id, set())
    return [_TECHNIQUES[tid] for tid in sub_ids if tid in _TECHNIQUES]


def resolve_techniques_from_text(
    text: str,
    max_results: int = 5,
    include_parent_boost: bool = True,
) -> List[TechniqueCandidate]:
    """
    Extract technique candidates from free text.
    
    Matching strategies (in order of confidence):
    1. Explicit IDs via regex (T1234, T1234.001) - score: 1.0
    2. Alias matching (e.g., "mimikatz" -> T1003.001) - score: 0.92
    3. Exact name match (normalized) - score: 0.90
    4. Fuzzy name match - score: varies (0.7-0.85)
    5. Parent technique boost (if sub-technique matched) - score: 0.5
    
    Args:
        text: Input text to analyze
        max_results: Maximum candidates to return
        include_parent_boost: If True, boost parent techniques when sub-techniques match
    
    Returns:
        List of TechniqueCandidate sorted by score descending
    """
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

    # 1) Explicit IDs via regex
    for match in TECHID_RE.finditer(text):
        tid = match.group(1).upper()
        rec = _TECHNIQUES.get(tid)
        _update_candidate(tid, rec.name if rec else "", 1.0, "id_regex")

    # 2) Alias matching
    for alias_norm, tech_ids in _ALIAS_INDEX.items():
        if alias_norm in text_norm:
            for tid in tech_ids:
                rec = _TECHNIQUES.get(tid)
                if rec:
                    _update_candidate(tid, rec.name, 0.92, "alias")

    # 3) Exact name match (normalized substring)
    for rec in _TECHNIQUES.values():
        if rec.normalized_name and len(rec.normalized_name) >= 4:  # Skip very short names
            if rec.normalized_name in text_norm:
                _update_candidate(rec.id, rec.name, 0.90, "name_exact")

    # 4) Fuzzy match (only for candidates not already high-confidence)
    for rec in _TECHNIQUES.values():
        if not rec.name or len(rec.name) < 5:
            continue
        
        existing = candidates.get(rec.id)
        if existing and existing.score >= 0.85:
            continue

        score = _fuzzy_score(rec.name, text_lower)
        if score >= 0.70:
            # Scale fuzzy scores to 0.70-0.85 range
            adjusted_score = 0.70 + (score - 0.70) * 0.5
            _update_candidate(rec.id, rec.name, adjusted_score, "name_fuzzy")

    # 5) Parent technique boost
    if include_parent_boost:
        matched_parents: Set[str] = set()
        for tid in list(candidates.keys()):
            rec = _TECHNIQUES.get(tid)
            if rec and rec.parent_id:
                matched_parents.add(rec.parent_id)
        
        for parent_id in matched_parents:
            if parent_id not in candidates:
                parent_rec = _TECHNIQUES.get(parent_id)
                if parent_rec:
                    _update_candidate(parent_id, parent_rec.name, 0.50, "parent_boost")

    # Sort by score descending, then by ID for stability
    sorted_candidates = sorted(
        candidates.values(),
        key=lambda c: (-c.score, c.id),
    )

    return sorted_candidates[:max_results]


def resolve_technique_id(text: str) -> Optional[str]:
    """
    Convenience function: resolve the single best technique ID from text.
    Returns None if no match found.
    """
    candidates = resolve_techniques_from_text(text, max_results=1)
    return candidates[0].id if candidates else None


# ---------------------------------------------------------------------------
# CLI for testing
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI for testing the resolver."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test technique resolver")
    parser.add_argument("text", nargs="+", help="Text to analyze")
    parser.add_argument("-n", "--max-results", type=int, default=5, help="Max results")
    parser.add_argument("--reload", action="store_true", help="Force reload index")
    
    args = parser.parse_args()
    text = " ".join(args.text)
    
    if args.reload:
        ensure_loaded(force=True)
    
    print(f"\n[resolver] Input: {text!r}\n")
    
    candidates = resolve_techniques_from_text(text, max_results=args.max_results)
    
    if not candidates:
        print("[resolver] No techniques found.")
        return
    
    print("[resolver] Candidates:")
    for c in candidates:
        print(f"  {c.id:12} | {c.score:.2f} | {c.source:12} | {c.name}")


if __name__ == "__main__":
    main()