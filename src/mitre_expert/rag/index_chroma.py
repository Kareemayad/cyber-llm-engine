"""
Index RAG chunks into ChromaDB with pluggable embedding backends.

Supports:
- MITRE ATT&CK chunks (mitre_chunks_v1)
- D3FEND defense chunks (d3fend_chunks_v1)

Embedding backends:
- HuggingFace sentence-transformers (default)
- Ollama (local LLM server)

FIXES:
- Issue 1: Now captures both analytic_id and analytic_stix_id
- Issue 2: Now stores analytic-level telemetry fields for proper ranking
- Issue 3: Now captures D3FEND primary_attack_technique for per-technique retrieval
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List

import chromadb
import requests
from chromadb.utils import embedding_functions

from mitre_expert.config import (
    CHROMA_DB_DIR,
    DATASETS,
    DatasetConfig,
    INDEX_BATCH_SIZE,
    EMBED_BACKEND,
    HF_EMBED_MODEL,
    OLLAMA_EMBED_MODEL,
    OLLAMA_BASE_URL,
    get_dataset_config,
    get_all_dataset_keys,
)


# ---------------------------------------------------------------------------
# Embedding backends
# ---------------------------------------------------------------------------

class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """Embedding function that calls Ollama locally."""

    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None) -> None:
        self.model = model
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self._session = requests.Session()

    def _post_json(self, path: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}{path}"
        return self._session.post(url, json=payload, timeout=60)

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not isinstance(input, list):
            raise TypeError("OllamaEmbeddingFunction expects a list[str] as input")

        # Try batch endpoint first
        try:
            resp = self._post_json("/api/embed", {"model": self.model, "input": input})
            if resp.status_code == 404:
                raise FileNotFoundError("/api/embed not found")
            resp.raise_for_status()

            data = resp.json()
            if "embeddings" in data and isinstance(data["embeddings"], list):
                return data["embeddings"]
            if "embedding" in data and isinstance(data["embedding"], list):
                return [data["embedding"]]
            raise ValueError(f"Unexpected /api/embed response keys={list(data.keys())}")

        except (FileNotFoundError, requests.HTTPError, ValueError) as embed_err:
            if isinstance(embed_err, requests.HTTPError):
                status = embed_err.response.status_code if embed_err.response is not None else None
                if status != 404:
                    body = embed_err.response.text[:500] if embed_err.response is not None else ""
                    raise RuntimeError(
                        f"Ollama /api/embed failed: status={status}, body={body}"
                    ) from embed_err

        # Fallback: one-by-one
        embeddings: List[List[float]] = []
        for text in input:
            resp = self._post_json("/api/embeddings", {"model": self.model, "prompt": text})
            try:
                resp.raise_for_status()
            except requests.HTTPError as e:
                raise RuntimeError(
                    f"Ollama /api/embeddings failed: status={resp.status_code}, body={resp.text[:500]}"
                ) from e

            data = resp.json()
            if "embedding" in data and isinstance(data["embedding"], list):
                embeddings.append(data["embedding"])
                continue
            if "embeddings" in data and isinstance(data["embeddings"], list) and data["embeddings"]:
                embeddings.append(data["embeddings"][0])
                continue
            raise ValueError(f"Unexpected /api/embeddings response keys={list(data.keys())}")

        return embeddings


class HFSentenceTransformerEmbedding(embedding_functions.EmbeddingFunction):
    """Embedding function using sentence-transformers on local CPU/GPU."""

    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer
        import torch

        self.model_name = model_name
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        print(f"[index] Loading sentence-transformers model: {model_name} on {device}")
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
        print(f"[index] Using HuggingFace sentence-transformers backend: {HF_EMBED_MODEL}")
        return HFSentenceTransformerEmbedding(HF_EMBED_MODEL)

    if backend == "ollama":
        print(f"[index] Using Ollama backend: model={OLLAMA_EMBED_MODEL} base_url={OLLAMA_BASE_URL}")
        return OllamaEmbeddingFunction(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_BASE_URL)

    raise ValueError(f"Unknown EMBED_BACKEND={backend!r}. Expected 'hf' or 'ollama'.")


# ---------------------------------------------------------------------------
# Chunk loading
# ---------------------------------------------------------------------------

def _load_chunks(path: Path) -> Iterable[Dict[str, Any]]:
    """Stream chunk records from JSONL."""
    if not path.exists():
        raise FileNotFoundError(f"Chunks file not found: {path}")

    print(f"[index] Loading chunks from {path} ...")
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


# ---------------------------------------------------------------------------
# Metadata handling
# ---------------------------------------------------------------------------

def _sanitize_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure Chroma-compatible metadata types.
    
    Chroma only supports: str, int, float, bool
    Lists/sets/tuples are joined into comma-separated strings.
    Dicts and complex objects are dropped (not queryable anyway).
    """
    safe: Dict[str, Any] = {}
    
    for k, v in meta.items():
        if v is None:
            continue

        # Primitive types: pass through
        if isinstance(v, (str, int, float, bool)):
            safe[k] = v
            continue

        # Lists/tuples/sets: join as comma-separated string
        if isinstance(v, (list, tuple, set)):
            # Filter out None and empty strings
            items = [str(x).strip() for x in v if x is not None and str(x).strip()]
            if items:
                safe[k] = ", ".join(items)
            continue

        # Dicts: skip (too complex for Chroma metadata)
        if isinstance(v, dict):
            # Could stringify, but not useful for queries
            continue

        # Fallback: stringify
        str_val = str(v).strip()
        if str_val:
            safe[k] = str_val

    return safe


def _build_metadata_from_record(rec: Dict[str, Any], dataset_key: str) -> Dict[str, Any]:
    """
    Build metadata dict for BOTH MITRE and D3FEND chunks.
    
    FIX Issue 1: Now captures both analytic_stix_id AND analytic_id
    FIX Issue 2: Now captures analytic-level telemetry fields
    FIX Issue 3: Now captures D3FEND primary_attack_technique
    """
    section = rec.get("section") or "unknown"
    chunk_id = rec.get("chunk_id") or rec.get("id")
    source = rec.get("source") or f"{dataset_key}_chunks_v1"

    meta_raw: Dict[str, Any] = {
        "chunk_id": chunk_id,
        "source": source,
        "dataset": dataset_key,
        "section": section,
        # Legacy aliases for backward compatibility
        "chunk_type": section,
        "type": section,
    }

    # --- MITRE technique-centric metadata ---
    mitre_fields = [
        # Core identifiers
        "technique_id",
        "technique_name",
        "tactic_ids",
        "tactic_names",
        "platforms",
        
        # Technique-level telemetry
        "data_component_ids",
        "log_source_names",
        
        # Mitigation metadata
        "mitigation_id",
        "mitigation_name",
        
        # Procedure metadata
        "procedure_source_id",
        "procedure_source_name",
        "procedure_source_type",
        
        # Detection strategy metadata
        "detection_strategy_stix_id",
        "detection_strategy_name",
        
        # Analytic metadata (FIX Issue 1)
        "analytic_stix_id",
        "analytic_name",
        
        # Analytic-level telemetry (FIX Issue 2)
        "analytic_data_component_ids",
        "analytic_log_source_names",
        # NOTE: analytic_log_source_references is List[Dict], not indexable
    ]
    
    for k in mitre_fields:
        if k in rec and rec[k] is not None:
            meta_raw[k] = rec[k]
    
    # FIX Issue 1: Set analytic_id as alias for analytic_stix_id
    if "analytic_stix_id" in rec and rec["analytic_stix_id"]:
        meta_raw["analytic_id"] = rec["analytic_stix_id"]
    elif "analytic_id" in rec and rec["analytic_id"]:
        meta_raw["analytic_id"] = rec["analytic_id"]

    # --- D3FEND defense-centric metadata ---
    d3fend_fields = [
        # Core identifiers
        "d3fend_id",
        "label",
        "uri",
        
        # ATT&CK technique mappings
        "attack_techniques",
        "primary_attack_technique",  # FIX Issue 3: Per-technique mapping
        
        # Relations
        "relation_types",
        "related_uris",
    ]
    
    for k in d3fend_fields:
        if k in rec and rec[k] is not None:
            meta_raw[k] = rec[k]

    return _sanitize_metadata(meta_raw)


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _parse_bool_env(name: str, default: bool) -> bool:
    """Parse boolean from environment variable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _select_datasets(target: str) -> List[DatasetConfig]:
    """Select datasets to index based on target string."""
    t = (target or "mitre").strip().lower()
    if t == "all":
        return DATASETS
    
    # Try to find by key
    config = get_dataset_config(t)
    if config:
        return [config]
    
    # Not found
    valid = ", ".join(get_all_dataset_keys()) + ", all"
    raise ValueError(f"Unknown target={target!r}. Valid: {valid}")


# ---------------------------------------------------------------------------
# Index one dataset
# ---------------------------------------------------------------------------

def _index_dataset(
    client: chromadb.PersistentClient,
    dataset: DatasetConfig,
    embed_fn: embedding_functions.EmbeddingFunction,
    drop_existing: bool,
) -> Dict[str, Any]:
    """
    Index a single dataset into ChromaDB.
    
    Returns statistics dict.
    """
    chunks_path = dataset.chunks_path
    collection_name = dataset.collection_name

    print(f"\n[index] ===== Dataset: {dataset.key} =====")
    print(f"[index] Input: {chunks_path}")
    print(f"[index] Collection: {collection_name}")

    # Drop existing if requested
    if drop_existing:
        try:
            print(f"[index] Deleting existing collection '{collection_name}' ...")
            client.delete_collection(name=collection_name)
        except Exception:
            print(f"[index] No existing collection '{collection_name}', creating fresh.")

    collection = client.get_or_create_collection(
        name=collection_name,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )

    # Track statistics
    stats = {
        "dataset": dataset.key,
        "total_indexed": 0,
        "duplicates_renamed": 0,
        "skipped_empty_text": 0,
        "empty_meta_fixed": 0,
        "sections": {},
    }

    seen_ids: set[str] = set()
    
    batch_ids: List[str] = []
    batch_docs: List[str] = []
    batch_metas: List[Dict[str, Any]] = []

    for idx, rec in enumerate(_load_chunks(chunks_path)):
        # Generate unique chunk ID
        base_id = str(rec.get("id") or rec.get("chunk_id") or f"{dataset.key}_chunk_{idx}")

        chunk_id = base_id
        if chunk_id in seen_ids:
            stats["duplicates_renamed"] += 1
            suffix = 1
            new_id = f"{base_id}::dup::{suffix}"
            while new_id in seen_ids:
                suffix += 1
                new_id = f"{base_id}::dup::{suffix}"
            chunk_id = new_id
            if stats["duplicates_renamed"] <= 10:
                print(f"[warn] Duplicate chunk id '{base_id}' renamed to '{chunk_id}'.")

        seen_ids.add(chunk_id)

        # Validate text
        text = rec.get("text")
        if not text or not isinstance(text, str) or not text.strip():
            stats["skipped_empty_text"] += 1
            continue

        # Build metadata
        meta_safe = _build_metadata_from_record(rec, dataset_key=dataset.key)

        if not meta_safe:
            stats["empty_meta_fixed"] += 1
            meta_safe = {
                "source": f"{dataset.key}_chunks_v1",
                "dataset": dataset.key,
                "section": "unknown",
            }

        # Track section distribution
        section = meta_safe.get("section", "unknown")
        stats["sections"][section] = stats["sections"].get(section, 0) + 1

        # Add to batch
        batch_ids.append(chunk_id)
        batch_docs.append(text)
        batch_metas.append(meta_safe)
        stats["total_indexed"] += 1

        # Flush batch
        if len(batch_ids) >= INDEX_BATCH_SIZE:
            collection.add(ids=batch_ids, documents=batch_docs, metadatas=batch_metas)
            print(f"[index] Inserted {stats['total_indexed']} chunks ...")
            batch_ids, batch_docs, batch_metas = [], [], []

    # Final batch
    if batch_ids:
        collection.add(ids=batch_ids, documents=batch_docs, metadatas=batch_metas)
        print(f"[index] Inserted {stats['total_indexed']} chunks (final batch).")

    # Summary
    print(f"\n[index] DONE dataset={dataset.key}")
    print(f"  Indexed: {stats['total_indexed']}")
    print(f"  Duplicates renamed: {stats['duplicates_renamed']}")
    if stats["skipped_empty_text"]:
        print(f"  Skipped (empty text): {stats['skipped_empty_text']}")
    if stats["empty_meta_fixed"]:
        print(f"  Fixed (empty metadata): {stats['empty_meta_fixed']}")
    print(f"  Sections: {stats['sections']}")

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def index_all(
    target: str = "mitre",
    drop_existing: bool = True,
) -> List[Dict[str, Any]]:
    """
    Index one or more datasets.
    
    Args:
        target: "mitre", "d3fend", or "all"
        drop_existing: If True, delete existing collection before indexing
    
    Returns:
        List of statistics dicts, one per dataset.
    """
    datasets = _select_datasets(target)
    embed_fn = get_embedding_function()

    print(f"[index] Connecting to Chroma at {CHROMA_DB_DIR} ...")
    CHROMA_DB_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DB_DIR))

    print(f"[index] Target={target!r} -> datasets={[d.key for d in datasets]} | drop_existing={drop_existing}")
    
    all_stats = []
    for ds in datasets:
        stats = _index_dataset(
            client=client,
            dataset=ds,
            embed_fn=embed_fn,
            drop_existing=drop_existing,
        )
        all_stats.append(stats)

    return all_stats


def main() -> None:
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Index MITRE/D3FEND chunks into ChromaDB")
    parser.add_argument(
        "--target", "-t",
        default=os.getenv("MITRE_INDEX_TARGET", "mitre"),
        choices=get_all_dataset_keys() + ["all"],
        help="Dataset(s) to index",
    )
    parser.add_argument(
        "--no-drop",
        action="store_true",
        help="Don't drop existing collection (append mode)",
    )
    
    args = parser.parse_args()
    
    drop_existing = not args.no_drop
    if os.getenv("MITRE_REINDEX_DROP") is not None:
        drop_existing = _parse_bool_env("MITRE_REINDEX_DROP", default=True)
    
    index_all(target=args.target, drop_existing=drop_existing)


if __name__ == "__main__":
    main()