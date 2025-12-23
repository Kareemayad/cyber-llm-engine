# src/mitre_expert/rag/query_chroma.py

"""
Query the MITRE Chroma index and inspect top-matching chunks.

Adds:
- Deterministic retrieval via collection.get(where=...) for enumeration tasks
- Chroma filter normalization for newer versions that require a single top-level operator
- Post-filters for --dc and --logsource (works across Chroma versions even with CSV metadata)

FIXES (perf + correctness):
- Cache PersistentClient, embedding function, and collections (avoid reloading HF model each call)
- Use a NO-EMBED collection for deterministic .get() (collection.get() does not need embeddings)
- Safer handling of limit=None for enumeration tasks (optional cap)
- Semantic technique aggregation uses MAX(sim) per technique (avoids bias toward chunk-rich techniques)
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
# Paths & constants (must match index_chroma.py)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
DB_DIR = REPO_ROOT / "data" / "embeddings" / "mitre" / "chroma"
COLLECTION_NAME = "mitre_chunks_v1"

_DEFAULT_GET_HARD_CAP = int(os.getenv("MITRE_GET_HARD_CAP", "500"))

# How many results to fetch before applying post-filters (dc/logsource)
_PREFETCH_K = int(os.getenv("MITRE_PREFETCH_K", "50"))  # sensible default


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
# Cached Chroma handles
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _cached_client() -> chromadb.PersistentClient:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(DB_DIR))


@lru_cache(maxsize=1)
def _cached_embed_fn() -> embedding_functions.EmbeddingFunction:
    return get_embedding_function()


@lru_cache(maxsize=1)
def get_collection_with_embed():
    client = _cached_client()
    embed_fn = _cached_embed_fn()
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
    )


@lru_cache(maxsize=1)
def get_collection_no_embed():
    client = _cached_client()
    return client.get_or_create_collection(name=COLLECTION_NAME)


# ---------------------------------------------------------------------------
# Post-filter helpers (dc/logsource membership)
# ---------------------------------------------------------------------------

def _parse_csv_field(v: Any) -> List[str]:
    """
    Metadata fields are stored as CSV strings (because Chroma metadata doesn't support lists).
    Accepts str or list-like just in case.
    """
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
    """
    Filter a query() or get()-normalized result in-place and return the same shape.
    """
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

    out = {
        "ids": [keep_ids],
        "documents": [keep_docs],
        "metadatas": [keep_metas],
        "distances": [keep_dists] if dists else [[]],
    }
    return out


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _apply_get_limit(limit: Optional[int]) -> Optional[int]:
    if limit is not None:
        return int(limit)
    cap = _DEFAULT_GET_HARD_CAP
    if cap <= 0:
        return None
    return cap


def get_mitre_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    collection = get_collection_no_embed()
    where_norm = normalize_where(where)
    lim = _apply_get_limit(limit)
    print(f"[query] Fetching by filter (where={where}, normalized={where_norm}, limit={limit} -> {lim})")

    out = collection.get(
        where=where_norm,
        limit=lim,
        include=["documents", "metadatas"],
    )

    normalized = {
        "ids": [out.get("ids", [])],
        "documents": [out.get("documents", [])],
        "metadatas": [out.get("metadatas", [])],
        "distances": [[]],
    }
    filtered = _filter_result(normalized, dc=dc, logsource=logsource)
    return filtered


def search_mitre_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Semantic query. We prefetch more than k, then apply post-filters, then trim to k.
    """
    collection = get_collection_with_embed()
    where_norm = normalize_where(where)

    # Prefetch to allow filters to work without starving results
    prefetch = max(int(k), _PREFETCH_K)
    if where:
        print(f"[query] Searching for: {query!r} (prefetch={prefetch}, want_k={k}, where={where_norm}, dc={dc}, logsource={logsource})")
    else:
        print(f"[query] Searching for: {query!r} (prefetch={prefetch}, want_k={k}, dc={dc}, logsource={logsource})")

    raw = collection.query(
        query_texts=[query],
        n_results=prefetch,
        include=["documents", "metadatas", "distances"],
        where=where_norm,
    )

    filtered = _filter_result(raw, dc=dc, logsource=logsource)

    # Trim to k after filters
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
# Technique detection helpers
# ---------------------------------------------------------------------------

def detect_techniques_from_query(
    query: str,
    detect_k: int = 30,
    max_candidates: int = 3,
) -> List[Tuple[str, float]]:
    collection = get_collection_with_embed()

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
    best = resolve_best_technique(query, max_results=3)
    if best:
        print(
            f"[query] Resolver picked technique_id={best.id} "
            f"(name={best.name!r}, score={best.score:.3f}, source={best.source})"
        )
        return search_mitre_chunks(query=query, k=k, where={"technique_id": best.id}, dc=dc, logsource=logsource)

    print("[query] Could not detect technique_id, falling back to global search.")
    return search_mitre_chunks(query=query, k=k, where=None, dc=dc, logsource=logsource)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query the MITRE Chroma RAG index (mitre_chunks_v1).",
    )
    parser.add_argument(
        "query",
        nargs="+",
        help="Natural language query text.",
    )
    parser.add_argument(
        "-k",
        "--topk",
        type=int,
        default=5,
        help="Number of results to return (default: 5).",
    )
    parser.add_argument(
        "--tech",
        "--technique",
        dest="technique_id",
        help="Optional MITRE technique ID to filter on (e.g., T1548, T1055.001).",
    )
    parser.add_argument(
        "--section",
        dest="section",
        help="Optional section filter (e.g., mitigation, description, detection_strategy).",
    )
    parser.add_argument(
        "--mode",
        choices=["search", "get"],
        default="search",
        help="search = semantic query (default), get = deterministic fetch by filter.",
    )
    parser.add_argument(
        "--dc",
        dest="data_components",
        action="append",
        help="Filter results to chunks that include this data component ID (repeatable), e.g. --dc DC0032",
    )
    parser.add_argument(
        "--logsource",
        dest="log_sources",
        action="append",
        help="Filter results to chunks that include this log source name (repeatable), e.g. --logsource azure:signinlogs",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    query_text = " ".join(args.query)

    where: Dict[str, Any] = {}
    if args.technique_id:
        where["technique_id"] = args.technique_id
    if args.section:
        where["section"] = args.section

    dc = [x.strip() for x in (args.data_components or []) if x and x.strip()]
    logsource = [x.strip() for x in (args.log_sources or []) if x and x.strip()]

    if args.mode == "get":
        if not where:
            print("[query] ERROR: --mode get requires at least one filter (e.g., --tech or --section).")
            sys.exit(2)
        result = get_mitre_chunks_by_filter(where=where, limit=args.topk, dc=dc, logsource=logsource)
    else:
        if where:
            result = search_mitre_chunks(query=query_text, k=args.topk, where=where, dc=dc, logsource=logsource)
        else:
            result = auto_search_mitre_chunks(query=query_text, k=args.topk, dc=dc, logsource=logsource)

    pretty_print_results(result)


if __name__ == "__main__":
    main()
