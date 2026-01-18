"""
Query the Chroma index for MITRE ATT&CK and D3FEND chunks.

Multi-dataset support:
  - MITRE collection: mitre_chunks_v1
  - D3FEND collection: d3fend_chunks_v1

Public API:
  - get_collection(dataset, with_embed=True/False)
  - search_chunks(dataset, query, ...)
  - get_chunks(dataset, where, ...)

Datasets:
  - "mitre" | "d3fend" | "all"
  - "all" merges results by best distance (semantic search only)

MITRE-specific:
  - Telemetry post-filters (dc, logsource)
  - Technique detection helpers

D3FEND-specific:
  - ATT&CK technique mapping search
"""

from __future__ import annotations

import argparse
import os
import sys
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple

import chromadb
from chromadb.utils import embedding_functions

from mitre_expert.config import (
    CHROMA_DB_DIR,
    MITRE_CHROMA_COLLECTION,
    D3FEND_CHROMA_COLLECTION,
    PREFETCH_K,
    GET_HARD_CAP,
    EMBED_BACKEND,
    HF_EMBED_MODEL,
    OLLAMA_EMBED_MODEL,
    OLLAMA_BASE_URL,
)
from mitre_expert.models.technique_resolver import (
    resolve_techniques_from_text,
    TechniqueCandidate,
)


# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------

def normalize_dataset(dataset: str | None) -> str:
    """Normalize and validate dataset name."""
    ds = (dataset or "mitre").strip().lower()
    if ds not in ("mitre", "d3fend", "all"):
        raise ValueError(f"Unknown dataset={dataset!r}. Expected 'mitre'|'d3fend'|'all'.")
    return ds


def collection_name_for(dataset: str) -> str:
    """Get collection name for a dataset."""
    ds = normalize_dataset(dataset)
    if ds == "mitre":
        return MITRE_CHROMA_COLLECTION
    if ds == "d3fend":
        return D3FEND_CHROMA_COLLECTION
    raise ValueError("collection_name_for() does not accept dataset='all'")


def datasets_for_all() -> List[str]:
    """Get list of all datasets for merged queries."""
    return ["mitre", "d3fend"]


# ---------------------------------------------------------------------------
# Embedding backends
# ---------------------------------------------------------------------------

class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """Embedding function that calls Ollama locally."""

    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None) -> None:
        import requests
        self.model = model
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self._session = requests.Session()

    def __call__(self, input: List[str]) -> List[List[float]]:
        import requests

        # Try batch endpoint first
        resp = self._session.post(
            f"{self.base_url}/api/embed",
            json={"model": self.model, "input": input},
            timeout=60,
        )
        if resp.status_code == 404:
            # Fallback: one-by-one
            out: List[List[float]] = []
            for t in input:
                r = self._session.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": t},
                    timeout=60,
                )
                r.raise_for_status()
                data = r.json()
                if "embedding" in data:
                    out.append(data["embedding"])
                elif "embeddings" in data and data["embeddings"]:
                    out.append(data["embeddings"][0])
                else:
                    raise ValueError(f"Unexpected Ollama response: {list(data.keys())}")
            return out

        resp.raise_for_status()
        data = resp.json()
        if "embeddings" in data:
            return data["embeddings"]
        if "embedding" in data:
            return [data["embedding"]]
        raise ValueError(f"Unexpected Ollama response: {list(data.keys())}")


class HFSentenceTransformerEmbedding(embedding_functions.EmbeddingFunction):
    """Embedding function using sentence-transformers."""

    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer
        import torch

        self.model_name = model_name
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        print(f"[embed] Loading sentence-transformers model: {model_name} on {device}")
        self.model = SentenceTransformer(model_name, device=device)

    def __call__(self, input: List[str]) -> List[List[float]]:
        embeddings = self.model.encode(
            input,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        return embeddings.tolist()


def get_embedding_function() -> embedding_functions.EmbeddingFunction:
    """Get embedding function based on environment configuration."""
    backend = EMBED_BACKEND

    if backend == "hf":
        print(f"[query] Using HuggingFace sentence-transformers backend: {HF_EMBED_MODEL}")
        return HFSentenceTransformerEmbedding(HF_EMBED_MODEL)

    if backend == "ollama":
        print(f"[query] Using Ollama backend: model={OLLAMA_EMBED_MODEL} base_url={OLLAMA_BASE_URL}")
        return OllamaEmbeddingFunction(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_BASE_URL)

    raise ValueError(f"Unknown EMBED_BACKEND={backend!r}. Expected 'hf' or 'ollama'.")


# ---------------------------------------------------------------------------
# Cached Chroma handles
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _cached_client() -> chromadb.PersistentClient:
    """Get cached Chroma client."""
    CHROMA_DB_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(CHROMA_DB_DIR))


@lru_cache(maxsize=1)
def _cached_embed_fn() -> embedding_functions.EmbeddingFunction:
    """Get cached embedding function."""
    return get_embedding_function()


@lru_cache(maxsize=16)
def get_collection(dataset: str = "mitre", with_embed: bool = True):
    """
    Get a Chroma collection.
    
    Args:
        dataset: "mitre" or "d3fend" (not "all")
        with_embed: If True, attach embedding function (needed for semantic queries)
    """
    ds = normalize_dataset(dataset)
    if ds == "all":
        raise ValueError("get_collection() does not accept dataset='all'")

    client = _cached_client()
    name = collection_name_for(ds)

    if with_embed:
        embed_fn = _cached_embed_fn()
        return client.get_or_create_collection(name=name, embedding_function=embed_fn)

    return client.get_or_create_collection(name=name)


# ---------------------------------------------------------------------------
# Filter normalization
# ---------------------------------------------------------------------------

def normalize_where(where: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Normalize filter dict for Chroma.
    
    Chroma requires a single top-level operator ($and, $or) when multiple conditions exist.
    """
    if not where:
        return None

    # Single condition: return as-is
    if len(where) == 1:
        only_key = next(iter(where.keys()))
        if isinstance(only_key, str) and only_key.startswith("$"):
            value = where[only_key]
            # Unwrap single-item $and/$or
            if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                return value[0]
            return where
        return where

    # Multiple conditions: wrap in $and
    clauses = [{k: v} for k, v in where.items()]
    return {"$and": clauses}


# ---------------------------------------------------------------------------
# Post-filter helpers
# ---------------------------------------------------------------------------

def _parse_csv_field(v: Any) -> List[str]:
    """Parse a possibly comma-separated metadata field into a list."""
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()] if str(v).strip() else []


def _match_any(meta: Dict[str, Any], key: str, wanted: Optional[List[str]]) -> bool:
    """Check if any wanted value exists in metadata field."""
    if not wanted:
        return True
    hay = set(_parse_csv_field(meta.get(key)))
    return any(w in hay for w in wanted)


def _match_any_substring(meta: Dict[str, Any], key: str, wanted: Optional[List[str]]) -> bool:
    """
    Check if any wanted value exists in metadata field (substring match).
    Used for fuzzy log source matching.
    """
    if not wanted:
        return True
    hay = _parse_csv_field(meta.get(key))
    hay_lower = [h.lower() for h in hay]
    for w in wanted:
        w_lower = w.lower()
        for h in hay_lower:
            if w_lower in h or h in w_lower:
                return True
    return False


def _filter_mitre_result(
    result: Dict[str, Any],
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Apply MITRE-specific post-filters (data components, log sources)."""
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
        
        # Check data components
        if not _match_any(meta, "data_component_ids", dc):
            if not _match_any(meta, "analytic_data_component_ids", dc):
                continue
        
        # Check log sources (use substring matching for flexibility)
        if logsource:
            matched = (
                _match_any_substring(meta, "log_source_names", logsource) or
                _match_any_substring(meta, "analytic_log_source_names", logsource)
            )
            if not matched:
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


def _filter_d3fend_result(
    result: Dict[str, Any],
    attack_technique: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply D3FEND-specific post-filters (ATT&CK technique)."""
    if not attack_technique:
        return result

    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if not ids:
        return result

    attack_technique = attack_technique.upper()
    
    keep_ids: List[str] = []
    keep_docs: List[str] = []
    keep_metas: List[Dict[str, Any]] = []
    keep_dists: List[float] = []

    for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
        meta = meta or {}
        
        # Check primary_attack_technique (exact match)
        primary = (meta.get("primary_attack_technique") or "").upper()
        if primary == attack_technique:
            keep_ids.append(cid)
            keep_docs.append(doc)
            keep_metas.append(meta)
            if dists and i < len(dists):
                keep_dists.append(dists[i])
            continue
        
        # Check attack_techniques list (contains)
        attack_list = _parse_csv_field(meta.get("attack_techniques"))
        if attack_technique in [t.upper() for t in attack_list]:
            keep_ids.append(cid)
            keep_docs.append(doc)
            keep_metas.append(meta)
            if dists and i < len(dists):
                keep_dists.append(dists[i])
            continue

    return {
        "ids": [keep_ids],
        "documents": [keep_docs],
        "metadatas": [keep_metas],
        "distances": [keep_dists] if dists else [[]],
    }


# ---------------------------------------------------------------------------
# Core query functions
# ---------------------------------------------------------------------------

def _apply_get_limit(limit: Optional[int]) -> Optional[int]:
    """Apply limit with optional hard cap."""
    if limit is not None:
        return int(limit)
    cap = GET_HARD_CAP
    return cap if cap > 0 else None


def get_chunks(
    dataset: str,
    where: Dict[str, Any],
    limit: Optional[int] = None,
    include: Optional[List[str]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
    attack_technique: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deterministic fetch via collection.get(where=...).
    
    Args:
        dataset: "mitre" or "d3fend" (not "all")
        where: Filter conditions
        limit: Max results (default: hard cap from env)
        include: Fields to include (default: documents, metadatas)
        dc: MITRE data component filter
        logsource: MITRE log source filter
        attack_technique: D3FEND ATT&CK technique filter
    """
    ds = normalize_dataset(dataset)
    if ds == "all":
        raise ValueError("get_chunks(dataset='all') is not supported")

    collection = get_collection(dataset=ds, with_embed=False)
    where_norm = normalize_where(where)
    lim = _apply_get_limit(limit)
    inc = include or ["documents", "metadatas"]

    out = collection.get(where=where_norm, limit=lim, include=inc)

    # Normalize to standard format
    normalized = {
        "ids": [out.get("ids", [])],
        "documents": [out.get("documents", [])],
        "metadatas": [out.get("metadatas", [])],
        "distances": [[]],
    }

    # Apply post-filters
    if ds == "mitre":
        normalized = _filter_mitre_result(normalized, dc=dc, logsource=logsource)
    elif ds == "d3fend":
        normalized = _filter_d3fend_result(normalized, attack_technique=attack_technique)

    return normalized


def search_chunks(
    dataset: str,
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
    attack_technique: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Semantic query.
    
    Args:
        dataset: "mitre", "d3fend", or "all"
        query: Search query text
        k: Number of results
        where: Optional filter conditions
        include: Fields to include
        dc: MITRE data component filter
        logsource: MITRE log source filter
        attack_technique: D3FEND ATT&CK technique filter
    """
    ds = normalize_dataset(dataset)
    where_norm = normalize_where(where)
    inc = include or ["documents", "metadatas", "distances"]

    if ds == "all":
        return _search_all(query=query, k=k, where=where_norm, include=inc)

    collection = get_collection(dataset=ds, with_embed=True)
    prefetch = max(int(k), PREFETCH_K)

    raw = collection.query(
        query_texts=[query],
        n_results=prefetch,
        include=inc,
        where=where_norm,
    )

    # Apply post-filters
    if ds == "mitre":
        filtered = _filter_mitre_result(raw, dc=dc, logsource=logsource)
    elif ds == "d3fend":
        filtered = _filter_d3fend_result(raw, attack_technique=attack_technique)
    else:
        filtered = raw

    # Trim to k
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
    """Semantic query across all datasets, merged by best distance."""
    inc = include or ["documents", "metadatas", "distances"]

    merged: List[Tuple[str, str, Dict[str, Any], float]] = []

    for ds in datasets_for_all():
        res = search_chunks(dataset=ds, query=query, k=max(k, PREFETCH_K), where=where, include=inc)
        ids = res.get("ids", [[]])[0]
        docs = res.get("documents", [[]])[0]
        metas = res.get("metadatas", [[]])[0]
        dists = res.get("distances", [[]])[0] if res.get("distances") else []

        for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
            dist = float(dists[i]) if dists and i < len(dists) else 1.0
            meta = meta or {}
            meta["dataset"] = ds
            merged.append((cid, doc, meta, dist))

    # Sort by distance (lower = better)
    merged.sort(key=lambda x: x[3])
    merged = merged[:k]

    return {
        "ids": [[x[0] for x in merged]],
        "documents": [[x[1] for x in merged]],
        "metadatas": [[x[2] for x in merged]],
        "distances": [[x[3] for x in merged]],
    }


# ---------------------------------------------------------------------------
# D3FEND-specific helpers (NEW)
# ---------------------------------------------------------------------------

def search_d3fend_for_technique(
    technique_id: str,
    k: int = 5,
    include_summary: bool = True,
) -> Dict[str, Any]:
    """
    Find D3FEND defenses that counter a specific ATT&CK technique.
    
    This is the key function for the merged /defend endpoint.
    
    Args:
        technique_id: ATT&CK technique ID (e.g., "T1059.001")
        k: Number of results
        include_summary: If True, also include attack_mappings summary chunks
    """
    technique_id = technique_id.upper()
    
    # Strategy 1: Direct filter on primary_attack_technique (per-technique mapping chunks)
    results = search_chunks(
        dataset="d3fend",
        query=f"defense countermeasure for {technique_id}",
        k=k * 2,  # Overfetch to allow filtering
        attack_technique=technique_id,
    )
    
    ids = results.get("ids", [[]])[0]
    
    # If we have enough results from per-technique chunks, return them
    if len(ids) >= k:
        return {
            "ids": [ids[:k]],
            "documents": [results.get("documents", [[]])[0][:k]],
            "metadatas": [results.get("metadatas", [[]])[0][:k]],
            "distances": [results.get("distances", [[]])[0][:k]] if results.get("distances") else [[]],
        }
    
    # Strategy 2: Broader semantic search
    broader = search_chunks(
        dataset="d3fend",
        query=f"defense countermeasure mitigation for ATT&CK technique {technique_id}",
        k=k,
    )
    
    # Merge and dedupe by d3fend_id
    seen_d3fend_ids: Set[str] = set()
    merged_ids: List[str] = []
    merged_docs: List[str] = []
    merged_metas: List[Dict[str, Any]] = []
    merged_dists: List[float] = []
    
    all_results = [
        (results.get("ids", [[]])[0], results.get("documents", [[]])[0], 
         results.get("metadatas", [[]])[0], results.get("distances", [[]])[0]),
        (broader.get("ids", [[]])[0], broader.get("documents", [[]])[0],
         broader.get("metadatas", [[]])[0], broader.get("distances", [[]])[0]),
    ]
    
    for ids, docs, metas, dists in all_results:
        for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
            d3fend_id = (meta or {}).get("d3fend_id", cid)
            if d3fend_id in seen_d3fend_ids:
                continue
            seen_d3fend_ids.add(d3fend_id)
            
            merged_ids.append(cid)
            merged_docs.append(doc)
            merged_metas.append(meta)
            if dists and i < len(dists):
                merged_dists.append(dists[i])
            else:
                merged_dists.append(1.0)
            
            if len(merged_ids) >= k:
                break
        if len(merged_ids) >= k:
            break
    
    return {
        "ids": [merged_ids],
        "documents": [merged_docs],
        "metadatas": [merged_metas],
        "distances": [merged_dists] if merged_dists else [[]],
    }


# ---------------------------------------------------------------------------
# Backward-compatible wrappers
# ---------------------------------------------------------------------------

def get_mitre_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible MITRE get wrapper."""
    return get_chunks(dataset="mitre", where=where, limit=limit, dc=dc, logsource=logsource)


def search_mitre_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible MITRE search wrapper."""
    return search_chunks(dataset="mitre", query=query, k=k, where=where, dc=dc, logsource=logsource)


def get_d3fend_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible D3FEND get wrapper."""
    return get_chunks(dataset="d3fend", where=where, limit=limit, include=include)


def search_d3fend_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible D3FEND search wrapper."""
    return search_chunks(dataset="d3fend", query=query, k=k, where=where, include=include)


# ---------------------------------------------------------------------------
# Technique detection helpers (MITRE-only)
# ---------------------------------------------------------------------------

def detect_techniques_from_query(
    query: str,
    detect_k: int = 30,
    max_candidates: int = 3,
) -> List[Tuple[str, float]]:
    """
    MITRE semantic technique detection.
    
    Returns list of (technique_id, similarity_score) tuples.
    Uses MAX(similarity) per technique to avoid bias toward chunk-rich techniques.
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

    # Use MAX similarity per technique
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
    MITRE technique resolver (regex/name match + semantic fallback).
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
    MITRE auto search: resolve technique then filter, or global search.
    """
    best = resolve_best_technique(query, max_results=3)
    if best:
        return search_mitre_chunks(query=query, k=k, where={"technique_id": best.id}, dc=dc, logsource=logsource)

    return search_mitre_chunks(query=query, k=k, where=None, dc=dc, logsource=logsource)


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

def pretty_print_results(result: Dict[str, Any]) -> None:
    """Print query results in a readable format."""
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if not ids:
        print("[query] No results.")
        return

    for rank, (cid, doc, meta) in enumerate(zip(ids, docs, metas), start=1):
        dist = dists[rank - 1] if dists and rank - 1 < len(dists) else None
        meta = meta or {}

        print("=" * 80)
        print(f"[{rank}] id={cid}")
        
        if meta.get("dataset"):
            print(f"    dataset:       {meta['dataset']}")
        if dist is not None:
            print(f"    distance:      {float(dist):.4f}")
        
        # MITRE fields
        if meta.get("technique_id"):
            tech_name = meta.get("technique_name", "")
            print(f"    technique:     {meta['technique_id']} {('- ' + tech_name) if tech_name else ''}")
        
        # D3FEND fields
        if meta.get("d3fend_id"):
            label = meta.get("label", "")
            print(f"    d3fend:        {meta['d3fend_id']} {('- ' + label) if label else ''}")
        if meta.get("primary_attack_technique"):
            print(f"    counters:      {meta['primary_attack_technique']}")
        
        print(f"    section:       {meta.get('section', 'unknown')}")
        
        if meta.get("mitigation_id"):
            print(f"    mitigation:    {meta['mitigation_id']} - {meta.get('mitigation_name', '')}")
        
        if meta.get("analytic_name"):
            print(f"    analytic:      {meta.get('analytic_stix_id', '')} - {meta['analytic_name']}")
        
        if meta.get("data_component_ids"):
            print(f"    data_components: {meta['data_component_ids']}")
        if meta.get("log_source_names"):
            print(f"    log_sources:     {meta['log_source_names']}")
        
        print("---- text ----")
        print((doc or "")[:1200])
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Query MITRE/D3FEND Chroma index")
    parser.add_argument("query", nargs="+", help="Query text")
    parser.add_argument("-k", "--topk", type=int, default=5, help="Number of results")
    parser.add_argument(
        "--dataset",
        choices=["mitre", "d3fend", "all"],
        default=os.getenv("RAG_TARGET", "mitre"),
        help="Dataset to query",
    )
    parser.add_argument(
        "--mode",
        choices=["search", "get"],
        default="search",
        help="Query mode",
    )
    parser.add_argument("--tech", dest="technique_id", help="MITRE technique_id filter")
    parser.add_argument("--section", help="Section filter")
    parser.add_argument("--attack", dest="attack_technique", help="D3FEND: filter by ATT&CK technique")
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
            print("[query] ERROR: --mode get is not supported with dataset=all")
            sys.exit(2)
        if not where:
            print("[query] ERROR: --mode get requires at least one filter")
            sys.exit(2)
        result = get_chunks(dataset=ds, where=where, limit=args.topk)
    else:
        if ds == "d3fend" and args.attack_technique:
            result = search_d3fend_for_technique(args.attack_technique, k=args.topk)
        else:
            result = search_chunks(
                dataset=ds,
                query=query_text,
                k=args.topk,
                where=where or None,
                attack_technique=args.attack_technique,
            )

    pretty_print_results(result)


if __name__ == "__main__":
    main()