# src/mitre_expert/knowledge_pack/build_d3fend_chunks.py
"""
Build D3FEND RAG chunks from the normalized defenses JSONL.

Input (hardcoded):
  data/processed/mitre/d3fend_defenses_v1.jsonl

Output (hardcoded):
  data/processed/mitre/d3fend_chunks_v1.jsonl

Chunk types (per defense):
  - definition
  - kb_article
  - relations
  - attack_mappings

Notes:
  - Defensive against schema drift: tries multiple keys.
  - Extracts ATT&CK technique IDs (Txxxx / Txxxx.xxx) wherever they appear.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Hardcoded IO paths (repo-relative, like build_knowledge_pack.py)
# ---------------------------------------------------------------------------

IN_JSONL = Path("data/processed/mitre/d3fend_defenses_v1.jsonl")
OUT_JSONL = Path("data/processed/mitre/d3fend_chunks_v1.jsonl")

SOURCE_NAME = "d3fend_chunks_v1"


# ----------------------------
# Small helpers
# ----------------------------

def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _clean_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x.strip()
    return str(x).strip()


def _get_first(d: Dict[str, Any], keys: List[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return None


def _extract_attack_ids(obj: Any) -> List[str]:
    """Walk any nested structure and extract ATT&CK technique IDs from strings."""
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

    # normalize + dedupe preserving order
    norm: List[str] = []
    seen = set()
    for t in found:
        tid = t.upper()
        if tid not in seen:
            seen.add(tid)
            norm.append(tid)
    return norm


def _extract_uri(x: Any) -> Optional[str]:
    """Common D3FEND JSON-LD pattern: {"@id": "..."} or plain string."""
    if isinstance(x, str):
        return x
    if isinstance(x, dict) and "@id" in x and isinstance(x["@id"], str):
        return x["@id"]
    return None


def _summarize_relations(rec: Dict[str, Any]) -> Tuple[str, List[str], List[str]]:
    """Build a readable relations summary text + return relation types + related URIs."""
    rel_keys = [
        # common relation keys seen in JSON-LD
        "d3f:related", "d3f:enables", "d3f:hardens", "d3f:spoofs", "d3f:monitors",
        "d3f:creates", "d3f:produces", "d3f:authenticates", "d3f:analyzes",
        "d3f:validates", "d3f:signs",
        # plus normalized variants (in case build_d3fend output renamed keys)
        "related", "enables", "hardens", "spoofs", "monitors",
        "creates", "produces", "authenticates", "analyzes",
        "validates", "signs",
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

        shown = uris[:12]
        more = f" (+{len(uris)-len(shown)} more)" if len(uris) > len(shown) else ""
        lines.append(f"- {k}: {', '.join(shown)}{more}")

    # dedupe related_uris preserving order
    seen = set()
    related_uris_dedup = []
    for u in related_uris:
        if u not in seen:
            seen.add(u)
            related_uris_dedup.append(u)

    if not lines:
        return "", [], []

    text = "Relations\n" + "\n".join(lines)
    return text, rel_types, related_uris_dedup


# ----------------------------
# Chunk model
# ----------------------------

@dataclass
class D3fendChunk:
    chunk_id: str
    section: str
    text: str

    # metadata
    source: str
    d3fend_id: str
    label: str
    uri: str

    attack_techniques: List[str]
    relation_types: List[str]
    related_uris: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
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


# ----------------------------
# IO
# ----------------------------

def _load_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
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
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


# ----------------------------
# Chunking logic
# ----------------------------

def iter_d3fend_chunks(defense: Dict[str, Any]) -> Iterator[D3fendChunk]:
    """Given a single defense record, yield chunks."""
    d3fend_id = _clean_text(_get_first(defense, ["d3fend_id", "d3f:d3fend-id", "id"])) or "UNKNOWN"
    label = _clean_text(_get_first(defense, ["label", "rdfs:label", "name", "pref_label", "skos:prefLabel"])) or d3fend_id
    uri = _clean_text(_get_first(defense, ["uri", "@id"])) or ""

    definition = _clean_text(_get_first(defense, ["definition", "d3f:definition"]))
    kb_article = _clean_text(_get_first(defense, ["kb_article", "d3f:kb-article"]))
    kb_refs = _get_first(defense, ["kb_reference", "d3f:kb-reference", "kb_references", "d3f:kb-reference-of"])

    rel_text, rel_types, rel_uris = _summarize_relations(defense)

    attack_ids = _extract_attack_ids({
        "defense": defense,
        "kb_refs": kb_refs,
    })

    # 1) definition
    if definition:
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_def",
            section="definition",
            text=f"{label}\n\nDefinition:\n{definition}",
            source=SOURCE_NAME,
            d3fend_id=d3fend_id,
            label=label,
            uri=uri,
            attack_techniques=attack_ids,
            relation_types=rel_types,
            related_uris=rel_uris,
        )

    # 2) kb_article
    if kb_article:
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_kb",
            section="kb_article",
            text=f"{label}\n\nKB Article:\n{kb_article}",
            source=SOURCE_NAME,
            d3fend_id=d3fend_id,
            label=label,
            uri=uri,
            attack_techniques=attack_ids,
            relation_types=rel_types,
            related_uris=rel_uris,
        )

    # 3) relations
    if rel_text:
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_rel",
            section="relations",
            text=f"{label}\n\n{rel_text}",
            source=SOURCE_NAME,
            d3fend_id=d3fend_id,
            label=label,
            uri=uri,
            attack_techniques=attack_ids,
            relation_types=rel_types,
            related_uris=rel_uris,
        )

    # 4) attack mappings
    if attack_ids:
        yield D3fendChunk(
            chunk_id=f"{d3fend_id}_attack",
            section="attack_mappings",
            text=f"{label}\n\nMapped ATT&CK Techniques:\n- " + "\n- ".join(attack_ids),
            source=SOURCE_NAME,
            d3fend_id=d3fend_id,
            label=label,
            uri=uri,
            attack_techniques=attack_ids,
            relation_types=rel_types,
            related_uris=rel_uris,
        )


def build_d3fend_chunks() -> None:
    print(f"[build] Loading D3FEND defenses from {IN_JSONL} ...")
    defenses = list(_load_jsonl(IN_JSONL))
    print(f"[build] Defenses loaded: {len(defenses)}")

    def chunk_dicts() -> Iterable[Dict[str, Any]]:
        for d in defenses:
            for c in iter_d3fend_chunks(d):
                if c.text and c.text.strip():
                    yield c.to_dict()

    print(f"[build] Writing D3FEND chunks to {OUT_JSONL} ...")
    n_chunks = _write_jsonl(OUT_JSONL, chunk_dicts())

    print("[done] D3FEND chunking complete")
    print(f"  Chunks written: {n_chunks}")
    print(f"  Output: {OUT_JSONL}")


if __name__ == "__main__":
    build_d3fend_chunks()
