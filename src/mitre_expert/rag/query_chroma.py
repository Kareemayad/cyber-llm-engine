# src/mitre_expert/rag/query_chroma.py

"""
Query the Chroma index and inspect top-matching chunks.

Multi-dataset support:
  - MITRE collection:   mitre_chunks_v1
  - D3FEND collection:  d3fend_chunks_v1

Public API (generic layer):
  - get_collection(dataset, with_embed=True/False)
  - search_chunks(dataset, query, ...)
  - get_chunks(dataset, where, ...)

Datasets:
  - "mitre" | "d3fend" | "all"
    - "all" is supported for semantic search only (merges results by best distance).

Adds:
- Deterministic retrieval via collection.get(where=...) for enumeration tasks
- Chroma filter normalization for newer versions that require a single top-level operator
- Post-filters for --dc and --logsource (works across Chroma versions even with CSV metadata)

FIXES (perf + correctness):
- Cache PersistentClient, embedding function, and collections (avoid reloading HF model each call)
- Use a NO-EMBED collection for deterministic .get() (collection.get() does not need embeddings)
- Safer handling of limit=None for enumeration tasks (optional cap)
- Semantic technique aggregation uses MAX(sim) per technique (avoids bias toward chunk-rich techniques)

NOTE:
- Technique resolution helpers remain MITRE-only.
"""

from __future__ import annotations

import argparse
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import chromadb
from chromadb.utils import embedding_functions

from mitre_expert.models.technique_resolver import (
    resolve_techniques_from_text,
    TechniqueCandidate,
)

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
DB_DIR = REPO_ROOT / "data" / "embeddings" / "mitre" / "chroma"

_DEFAULT_GET_HARD_CAP = int(os.getenv("MITRE_GET_HARD_CAP", "500"))
_PREFETCH_K = int(os.getenv("MITRE_PREFETCH_K", "50"))  # sensible default


# ---------------------------------------------------------------------------
# Dataset selection
# ---------------------------------------------------------------------------

def normalize_dataset(dataset: str | None) -> str:
    ds = (dataset or "mitre").strip().lower()
    if ds not in ("mitre", "d3fend", "all"):
        raise ValueError(f"Unknown dataset={dataset!r}. Expected 'mitre'|'d3fend'|'all'.")
    return ds


def collection_name_for(dataset: str) -> str:
    ds = normalize_dataset(dataset)
    if ds == "mitre":
        return "mitre_chunks_v1"
    if ds == "d3fend":
        return "d3fend_chunks_v1"
    raise ValueError("collection_name_for() does not accept dataset='all'")


def datasets_for_all() -> List[str]:
    return ["mitre", "d3fend"]


# ---------------------------------------------------------------------------
# Embedding backends (same logic as index_chroma.py)
# ---------------------------------------------------------------------------

class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None) -> None:
        import requests
        self.model = model
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self._session = requests.Session()

    def __call__(self, input: List[str]) -> List[List[float]]:
        import requests

        # Prefer /api/embed (batch) when available
        resp = self._session.post(
            f"{self.base_url}/api/embed",
            json={"model": self.model, "input": input},
            timeout=60,
        )
        if resp.status_code == 404:
            # fallback: /api/embeddings one-by-one
            out: List[List[float]] = []
            for t in input:
                r = self._session.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": t},
                    timeout=60,
                )
                try:
                    r.raise_for_status()
                except requests.HTTPError as e:
                    raise RuntimeError(
                        f"Ollama /api/embeddings failed: status={r.status_code}, body={r.text[:500]}"
                    ) from e
                data = r.json()
                if "embedding" in data:
                    out.append(data["embedding"])
                elif "embeddings" in data and data["embeddings"]:
                    out.append(data["embeddings"][0])
                else:
                    raise ValueError(f"Unexpected Ollama embeddings response keys={list(data.keys())}")
            return out

        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            raise RuntimeError(
                f"Ollama /api/embed failed: status={resp.status_code}, body={resp.text[:500]}"
            ) from e

        data = resp.json()
        if "embeddings" in data:
            return data["embeddings"]
        if "embedding" in data:
            return [data["embedding"]]
        raise ValueError(f"Unexpected Ollama embed response keys={list(data.keys())}")


class HFSentenceTransformerEmbedding(embedding_functions.EmbeddingFunction):
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer
        self.model_name = model_name
        print(f"[query] Loading sentence-transformers model: {model_name}")
        self.model = SentenceTransformer(model_name)

    def __call__(self, input: List[str]) -> List[List[float]]:
        embeddings = self.model.encode(
            input,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        return embeddings.tolist()


def get_embedding_function() -> embedding_functions.EmbeddingFunction:
    backend = os.getenv("MITRE_EMBED_BACKEND", "hf").lower()

    if backend == "hf":
        model_name = os.getenv("MITRE_HF_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        print(f"[query] Using HuggingFace sentence-transformers backend: {model_name}")
        return HFSentenceTransformerEmbedding(model_name)

    if backend == "ollama":
        model_name = os.getenv("MITRE_OLLAMA_EMBED_MODEL", "nomic-embed-text")
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        print(f"[query] Using Ollama backend: model={model_name} base_url={base_url}")
        return OllamaEmbeddingFunction(model=model_name, base_url=base_url)

    raise ValueError(f"Unknown MITRE_EMBED_BACKEND={backend!r}. Expected 'hf' or 'ollama'.")


# ---------------------------------------------------------------------------
# Filter normalization
# ---------------------------------------------------------------------------

def normalize_where(where: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not where:
        return None

    if len(where) == 1:
        only_key = next(iter(where.keys()))
        if isinstance(only_key, str) and only_key.startswith("$"):
            value = where[only_key]
            if isinstance(value, list) and len(value) >= 2:
                return where
            if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                return value[0]
            return where
        return where

    clauses: List[Dict[str, Any]] = [{k: v} for k, v in where.items()]
    return {"$and": clauses}


# ---------------------------------------------------------------------------
# Cached Chroma handles (generic selector)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _cached_client() -> chromadb.PersistentClient:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(DB_DIR))


@lru_cache(maxsize=1)
def _cached_embed_fn() -> embedding_functions.EmbeddingFunction:
    return get_embedding_function()


@lru_cache(maxsize=16)
def get_collection(dataset: str = "mitre", with_embed: bool = True):
    """
    Generic collection selector.

    dataset:
      - "mitre" | "d3fend"
    with_embed:
      - True  -> attaches embedding function (needed for semantic query)
      - False -> no embedding function (faster for .get())
    """
    ds = normalize_dataset(dataset)
    if ds == "all":
        raise ValueError("get_collection(dataset='all') is not valid; use search_chunks(dataset='all', ...) instead.")

    client = _cached_client()
    name = collection_name_for(ds)

    if with_embed:
        embed_fn = _cached_embed_fn()
        return client.get_or_create_collection(name=name, embedding_function=embed_fn)

    return client.get_or_create_collection(name=name)


# ---------------------------------------------------------------------------
# Post-filter helpers (MITRE telemetry filters; safe no-ops for D3FEND)
# ---------------------------------------------------------------------------

def _parse_csv_field(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()] if str(v).strip() else []


def _match_any(meta: Dict[str, Any], key: str, wanted: Optional[List[str]]) -> bool:
    if not wanted:
        return True
    hay = set(_parse_csv_field(meta.get(key)))
    return any(w in hay for w in wanted)


def _filter_result(
    result: Dict[str, Any],
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if not ids:
        return result

    keep_ids: List[str] = []
    keep_docs: List[str] = []
    keep_metas: List[Dict[str, Any]] = []
    keep_dists: List[float] = []

    for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
        meta = meta or {}
        if not _match_any(meta, "data_component_ids", dc):
            continue
        if not _match_any(meta, "log_source_names", logsource):
            continue

        keep_ids.append(cid)
        keep_docs.append(doc)
        keep_metas.append(meta)
        if dists and i < len(dists):
            keep_dists.append(dists[i])

    return {
        "ids": [keep_ids],
        "documents": [keep_docs],
        "metadatas": [keep_metas],
        "distances": [keep_dists] if dists else [[]],
    }


# ---------------------------------------------------------------------------
# Generic core functions
# ---------------------------------------------------------------------------

def _apply_get_limit(limit: Optional[int]) -> Optional[int]:
    if limit is not None:
        return int(limit)
    cap = _DEFAULT_GET_HARD_CAP
    if cap <= 0:
        return None
    return cap


def get_chunks(
    dataset: str,
    where: Dict[str, Any],
    limit: Optional[int] = None,
    include: Optional[List[str]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Deterministic fetch via collection.get(where=...).

    dataset:
      - "mitre" | "d3fend"
      - (NOT "all")

    include defaults to ["documents", "metadatas"].

    dc/logsource:
      - Applies post-filtering if those fields exist (MITRE).
      - Safe no-op on D3FEND.
    """
    ds = normalize_dataset(dataset)
    if ds == "all":
        raise ValueError("get_chunks(dataset='all') is not supported (ambiguous).")

    collection = get_collection(dataset=ds, with_embed=False)
    where_norm = normalize_where(where)
    lim = _apply_get_limit(limit)

    inc = include or ["documents", "metadatas"]

    print(f"[query] GET dataset={ds} where={where_norm} limit={limit}->{lim} include={inc}")

    out = collection.get(
        where=where_norm,
        limit=lim,
        include=inc,
    )

    normalized = {
        "ids": [out.get("ids", [])],
        "documents": [out.get("documents", [])],
        "metadatas": [out.get("metadatas", [])],
        "distances": [[]],
    }
    return _filter_result(normalized, dc=dc, logsource=logsource)


def search_chunks(
    dataset: str,
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Semantic query.

    dataset:
      - "mitre" | "d3fend" | "all"
        - "all" merges results across both collections by best distance.

    where:
      - Optional filter dict; for "all" you should only use filters that exist in both datasets.

    dc/logsource:
      - MITRE-only post-filters; safe no-op for D3FEND.
      - For dataset="all": we apply dc/logsource only to MITRE results.
    """
    ds = normalize_dataset(dataset)
    where_norm = normalize_where(where)
    inc = include or ["documents", "metadatas", "distances"]

    if ds == "all":
        return _search_all(query=query, k=k, where=where_norm, include=inc)

    collection = get_collection(dataset=ds, with_embed=True)
    prefetch = max(int(k), _PREFETCH_K)

    print(f"[query] SEARCH dataset={ds} query={query!r} prefetch={prefetch} k={k} where={where_norm}")

    raw = collection.query(
        query_texts=[query],
        n_results=prefetch,
        include=inc,
        where=where_norm,
    )

    filtered = _filter_result(raw, dc=dc, logsource=logsource)

    ids = filtered.get("ids", [[]])[0][:k]
    docs = filtered.get("documents", [[]])[0][:k]
    metas = filtered.get("metadatas", [[]])[0][:k]
    dists = filtered.get("distances", [[]])[0][:k] if filtered.get("distances") else []

    return {
        "ids": [ids],
        "documents": [docs],
        "metadatas": [metas],
        "distances": [dists] if dists else [[]],
    }


def _search_all(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Semantic query across BOTH datasets and merge top-k by best distance.

    Notes:
    - We do not apply MITRE-only post-filters here at merge time.
    - We add meta['dataset'] so callers can attribute results.
    """
    inc = include or ["documents", "metadatas", "distances"]

    merged: List[Tuple[str, str, Dict[str, Any], float]] = []

    for ds in datasets_for_all():
        res = search_chunks(dataset=ds, query=query, k=max(k, _PREFETCH_K), where=where, include=inc)
        ids = res.get("ids", [[]])[0]
        docs = res.get("documents", [[]])[0]
        metas = res.get("metadatas", [[]])[0]
        dists = res.get("distances", [[]])[0] if res.get("distances") else []

        for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
            dist = float(dists[i]) if dists and i < len(dists) else 1.0
            meta = meta or {}
            meta["dataset"] = ds
            merged.append((cid, doc, meta, dist))

    merged.sort(key=lambda x: x[3])  # smaller distance = better
    merged = merged[:k]

    return {
        "ids": [[x[0] for x in merged]],
        "documents": [[x[1] for x in merged]],
        "metadatas": [[x[2] for x in merged]],
        "distances": [[x[3] for x in merged]],
    }


# ---------------------------------------------------------------------------
# Backward-compatible wrappers (keep existing imports working)
# ---------------------------------------------------------------------------

def get_mitre_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return get_chunks(dataset="mitre", where=where, limit=limit, dc=dc, logsource=logsource)


def search_mitre_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return search_chunks(dataset="mitre", query=query, k=k, where=where, dc=dc, logsource=logsource)


# ✅ NEW: D3FEND wrappers (fixes ImportError in d3fend_docqa.py)

def get_d3fend_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Deterministic fetch for D3FEND via collection.get(where=...).
    Mirrors the MITRE wrapper style for compatibility.
    """
    return get_chunks(dataset="d3fend", where=where, limit=limit, include=include)


def search_d3fend_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Semantic query for D3FEND.
    This exists primarily to keep LLM modules/router imports stable.
    """
    return search_chunks(dataset="d3fend", query=query, k=k, where=where, include=include)


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

def pretty_print_results(result: Dict[str, Any]) -> None:
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if not ids:
        print("[query] No results.")
        return

    for rank, (cid, doc, meta) in enumerate(zip(ids, docs, metas), start=1):
        dist = None
        if dists and rank - 1 < len(dists):
            dist = dists[rank - 1]

        meta = meta or {}
        ds = meta.get("dataset")

        tech_id = meta.get("technique_id", "unknown")
        tech_name = meta.get("technique_name", "")
        source = meta.get("source", "unknown")
        section = meta.get("section", meta.get("chunk_type", meta.get("type", "unknown")))

        mit_id = meta.get("mitigation_id")
        mit_name = meta.get("mitigation_name")

        dcs = meta.get("data_component_ids", "")
        lss = meta.get("log_source_names", "")

        print("=" * 80)
        print(f"[{rank}] id={cid}")
        if ds:
            print(f"    dataset:       {ds}")
        if dist is not None:
            print(f"    distance:      {float(dist):.4f}")
        print(f"    technique:     {tech_id} {('- ' + tech_name) if tech_name else ''}")
        print(f"    section:       {section}")
        if mit_id or mit_name:
            s = f"{mit_id or ''} {('- ' + mit_name) if mit_name else ''}".strip()
            print(f"    mitigation:    {s}")
        print(f"    source:        {source}")
        if dcs:
            print(f"    data_components: {dcs}")
        if lss:
            print(f"    log_sources:     {lss}")
        print("---- text ----")
        print((doc or "")[:1200])
        print()


# ---------------------------------------------------------------------------
# Technique detection helpers (MITRE-only)
# ---------------------------------------------------------------------------

def detect_techniques_from_query(
    query: str,
    detect_k: int = 30,
    max_candidates: int = 3,
) -> List[Tuple[str, float]]:
    """
    MITRE-only semantic technique detection.
    Uses the MITRE collection metadata technique_id.
    """
    collection = get_collection(dataset="mitre", with_embed=True)

    raw = collection.query(
        query_texts=[query],
        n_results=detect_k,
        include=["metadatas", "distances"],
    )

    metas = raw.get("metadatas", [[]])[0]
    dists = raw.get("distances", [[]])[0]

    if not metas:
        return []

    tech_best: Dict[str, float] = {}
    for meta, dist in zip(metas, dists):
        meta = meta or {}
        tech_id = meta.get("technique_id")
        if not tech_id:
            continue
        sim = 1.0 - float(dist)
        prev = tech_best.get(tech_id)
        if prev is None or sim > prev:
            tech_best[tech_id] = sim

    ranked = sorted(tech_best.items(), key=lambda x: x[1], reverse=True)
    return ranked[:max_candidates]


def resolve_best_technique(
    query: str,
    max_results: int = 3,
) -> Optional[TechniqueCandidate]:
    """
    MITRE-only technique resolver (id regex/name match + semantic backstop).
    """
    resolved = resolve_techniques_from_text(query, max_results=max_results)
    if resolved:
        return resolved[0]

    semantic_cands = detect_techniques_from_query(query, detect_k=30, max_candidates=max_results)
    if semantic_cands:
        best_tech, score = semantic_cands[0]
        return TechniqueCandidate(id=best_tech, name="", score=float(score), source="semantic")

    return None


def auto_search_mitre_chunks(
    query: str,
    k: int = 5,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    MITRE-only auto search:
    - resolve technique id, then filter
    - else global MITRE search
    """
    best = resolve_best_technique(query, max_results=3)
    if best:
        print(
            f"[query] Resolver picked technique_id={best.id} "
            f"(name={best.name!r}, score={best.score:.3f}, source={best.source})"
        )
        return search_mitre_chunks(query=query, k=k, where={"technique_id": best.id}, dc=dc, logsource=logsource)

    print("[query] Could not detect technique_id, falling back to global MITRE search.")
    return search_mitre_chunks(query=query, k=k, where=None, dc=dc, logsource=logsource)


# ---------------------------------------------------------------------------
# CLI entrypoint (dataset aware)
# ---------------------------------------------------------------------------

def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query the Chroma RAG index (MITRE/D3FEND).",
    )
    parser.add_argument("query", nargs="+", help="Natural language query text.")
    parser.add_argument("-k", "--topk", type=int, default=5, help="Number of results to return.")
    parser.add_argument(
        "--dataset",
        choices=["mitre", "d3fend", "all"],
        default=os.getenv("RAG_TARGET", "mitre"),
        help="Dataset to query (default from env RAG_TARGET).",
    )
    parser.add_argument(
        "--mode",
        choices=["search", "get"],
        default="search",
        help="search = semantic query, get = deterministic fetch by filter.",
    )
    parser.add_argument("--tech", dest="technique_id", help="MITRE technique_id filter (MITRE only).")
    parser.add_argument("--section", dest="section", help="Optional section filter.")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    query_text = " ".join(args.query)

    where: Dict[str, Any] = {}
    if args.technique_id:
        where["technique_id"] = args.technique_id
    if args.section:
        where["section"] = args.section

    ds = normalize_dataset(args.dataset)

    if args.mode == "get":
        if ds == "all":
            print("[query] ERROR: --mode get is not supported with dataset=all (ambiguous collection).")
            sys.exit(2)
        if not where:
            print("[query] ERROR: --mode get requires at least one filter (e.g., --tech or --section).")
            sys.exit(2)
        result = get_chunks(dataset=ds, where=where, limit=args.topk)
    else:
        result = search_chunks(dataset=ds, query=query_text, k=args.topk, where=where or None)

    pretty_print_results(result)


if __name__ == "__main__":
    main()
