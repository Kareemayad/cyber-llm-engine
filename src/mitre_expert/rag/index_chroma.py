# src/mitre_expert/rag/index_chroma.py
"""
Index RAG chunks into ChromaDB with pluggable embedding backends.

Supports multiple datasets:
- MITRE ATT&CK chunks (mitre_chunks_v1.jsonl) -> collection "mitre_chunks_v1"
- MITRE D3FEND chunks (d3fend_chunks_v1.jsonl) -> collection "d3fend_chunks_v1"

Control via env:
  MITRE_INDEX_TARGET = "mitre" (default) | "d3fend" | "all"
  MITRE_REINDEX_DROP = "true" (default) | "false"

Embedding backends (select via env):
  MITRE_EMBED_BACKEND:
    - "hf"      -> HuggingFace sentence-transformers (default)
    - "ollama"  -> Ollama local embeddings

  For HF:
    MITRE_HF_EMBED_MODEL (default: "sentence-transformers/all-MiniLM-L6-v2")

  For Ollama:
    MITRE_OLLAMA_EMBED_MODEL (default: "nomic-embed-text")
    OLLAMA_BASE_URL (default: "http://localhost:11434")

Chroma persistent DB:
  data/embeddings/mitre/chroma/
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import chromadb
import requests
from chromadb.utils import embedding_functions

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
DB_DIR = REPO_ROOT / "data/embeddings/mitre/chroma"
BATCH_SIZE = 64  # how many chunks per Chroma .add call


@dataclass(frozen=True)
class DatasetConfig:
    key: str
    chunks_path: Path
    collection_name: str


DATASETS: List[DatasetConfig] = [
    DatasetConfig(
        key="mitre",
        chunks_path=REPO_ROOT / "data/processed/mitre/mitre_chunks_v1.jsonl",
        collection_name="mitre_chunks_v1",
    ),
    DatasetConfig(
        key="d3fend",
        chunks_path=REPO_ROOT / "data/processed/mitre/d3fend_chunks_v1.jsonl",
        collection_name="d3fend_chunks_v1",
    ),
]


# ---------------------------------------------------------------------------
# Embedding backends
# ---------------------------------------------------------------------------


class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """
    Embedding function that calls Ollama locally.

    Preferred endpoint:
      POST /api/embed   payload: {"model": "...", "input": "text" | ["t1","t2"] }
      response: {"embeddings": [[...], [...]]}

    Fallback endpoint:
      POST /api/embeddings  payload: {"model": "...", "prompt": "text"}
      response: {"embedding": [...]}
    """

    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None) -> None:
        self.model = model
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip(
            "/"
        )
        self._session = requests.Session()

    def _post_json(self, path: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}{path}"
        return self._session.post(url, json=payload, timeout=60)

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not isinstance(input, list):
            raise TypeError("OllamaEmbeddingFunction expects a list[str] as input")

        # ---- 1) Try /api/embed (supports batch)
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

        # ---- 2) Fallback: /api/embeddings (single prompt per request)
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

        self.model_name = model_name
        print(f"[index] Loading sentence-transformers model: {model_name}")
        self.model = SentenceTransformer(model_name)

    def __call__(self, input: List[str]) -> List[List[float]]:
        embeddings = self.model.encode(
            input,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        return embeddings.tolist()


def get_embedding_function():
    """Decide which embedding backend to use based on env variables."""
    backend = os.getenv("MITRE_EMBED_BACKEND", "hf").lower()

    if backend == "hf":
        model_name = os.getenv("MITRE_HF_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        print(f"[index] Using HuggingFace sentence-transformers backend: {model_name}")
        return HFSentenceTransformerEmbedding(model_name)

    if backend == "ollama":
        model_name = os.getenv("MITRE_OLLAMA_EMBED_MODEL", "nomic-embed-text")
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        print(f"[index] Using Ollama backend: model={model_name} base_url={base_url}")
        return OllamaEmbeddingFunction(model=model_name, base_url=base_url)

    raise ValueError(f"Unknown MITRE_EMBED_BACKEND={backend!r}. Expected 'hf' or 'ollama'.")


# ---------------------------------------------------------------------------
# Helpers for loading chunks & sanitizing metadata
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


def _sanitize_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure Chroma-compatible metadata types.

    IMPORTANT: Chroma rejects None values. So:
      - Any key with value None is DROPPED.
      - Lists/sets/tuples are joined into a comma-separated string,
        and None elements are dropped.
      - Empty lists become DROPPED.
      - Other objects become str(value).

    Output values are only: str | int | float | bool
    """
    safe: Dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue

        if isinstance(v, (str, int, float, bool)):
            safe[k] = v
            continue

        if isinstance(v, (list, tuple, set)):
            items = [str(x) for x in v if x is not None]
            if not items:
                continue
            safe[k] = ", ".join(items)
            continue

        safe[k] = str(v)

    return safe


def _build_metadata_from_record(rec: Dict[str, Any], dataset_key: str) -> Dict[str, Any]:
    """
    Build a metadata dict that works for BOTH MITRE and D3FEND chunk records.

    MITRE fields we expect:
      technique_id, technique_name, section, tactic_ids, tactic_names, platforms,
      data_component_ids, log_source_names, mitigation_id, analytic_id, etc.

    D3FEND fields we expect (from build_d3fend_chunks.py outputs):
      d3fend_id, label/name, section, attack_ids / attack_technique_ids, relations, etc.

    We store all "common" keys AND a few dataset-specific keys if present.
    """
    section = rec.get("section") or "unknown"

    # Common identifiers
    chunk_id = rec.get("chunk_id") or rec.get("id")
    source = rec.get("source") or (f"{dataset_key}_chunks_v1")

    meta_raw: Dict[str, Any] = {
        "chunk_id": chunk_id,
        "source": source,
        "dataset": dataset_key,
        "section": section,
        "chunk_type": section,
        "type": section,
    }

    # --- MITRE technique-centric metadata (if present)
    for k in [
        "technique_id",
        "technique_name",
        "tactic_ids",
        "tactic_names",
        "platforms",
        "data_component_ids",
        "log_source_names",
        "mitigation_id",
        "mitigation_name",
        "analytic_id",
        "analytic_name",
        "procedure_source_id",
        "procedure_source_name",
        "procedure_source_type",
    ]:
        if k in rec:
            meta_raw[k] = rec.get(k)

    # --- D3FEND defense-centric metadata (if present)
    # (your normalized + chunk scripts may use slightly different field names; we capture common variants)
    for k in [
        "d3fend_id",
        "d3fend_uri",
        "label",
        "name",
        "definition",
        "attack_id",  # sometimes a single
        "attack_ids",  # sometimes a list
        "attack_technique_ids",
        "attack_techniques",
        "related_uris",
        "related_ids",
        "related_labels",
        "relation_types",
    ]:
        if k in rec:
            meta_raw[k] = rec.get(k)

    return _sanitize_metadata(meta_raw)


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _select_datasets(target: str) -> List[DatasetConfig]:
    t = (target or "mitre").strip().lower()
    if t == "all":
        return DATASETS
    chosen = [d for d in DATASETS if d.key == t]
    if not chosen:
        valid = ", ".join(d.key for d in DATASETS) + ", all"
        raise ValueError(f"Unknown MITRE_INDEX_TARGET={target!r}. Valid: {valid}")
    return chosen


# ---------------------------------------------------------------------------
# Index one dataset
# ---------------------------------------------------------------------------


def _index_dataset(
    client: chromadb.PersistentClient,
    dataset: DatasetConfig,
    embed_fn: embedding_functions.EmbeddingFunction,
    drop_existing: bool,
) -> None:
    chunks_path = dataset.chunks_path
    collection_name = dataset.collection_name

    print(f"\n[index] ===== Dataset: {dataset.key} =====")
    print(f"[index] Input: {chunks_path}")
    print(f"[index] Collection: {collection_name}")

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

    seen_ids: set[str] = set()
    dup_count = 0
    skipped_empty_text = 0
    empty_meta_fixed = 0
    total = 0

    batch_ids: List[str] = []
    batch_docs: List[str] = []
    batch_metas: List[Dict[str, Any]] = []

    for idx, rec in enumerate(_load_chunks(chunks_path)):
        base_id = str(rec.get("id") or rec.get("chunk_id") or f"{dataset.key}_chunk_{idx}")

        chunk_id = base_id
        if chunk_id in seen_ids:
            dup_count += 1
            suffix = 1
            new_id = f"{base_id}::dup::{suffix}"
            while new_id in seen_ids:
                suffix += 1
                new_id = f"{base_id}::dup::{suffix}"
            chunk_id = new_id
            if dup_count <= 10:
                print(f"[warn] Duplicate chunk id '{base_id}' found. Renamed to '{chunk_id}'.")

        seen_ids.add(chunk_id)

        text = rec.get("text")
        if not text or not isinstance(text, str) or not text.strip():
            skipped_empty_text += 1
            continue

        meta_safe = _build_metadata_from_record(rec, dataset_key=dataset.key)

        # Chroma requires non-empty metadata dicts.
        if not meta_safe:
            empty_meta_fixed += 1
            meta_safe = {"source": f"{dataset.key}_chunks_v1", "dataset": dataset.key, "section": "unknown"}

        batch_ids.append(chunk_id)
        batch_docs.append(text)
        batch_metas.append(meta_safe)
        total += 1

        if len(batch_ids) >= BATCH_SIZE:
            collection.add(ids=batch_ids, documents=batch_docs, metadatas=batch_metas)
            print(f"[index] Inserted {total} chunks ...")
            batch_ids, batch_docs, batch_metas = [], [], []

    if batch_ids:
        collection.add(ids=batch_ids, documents=batch_docs, metadatas=batch_metas)
        print(f"[index] Inserted {total} chunks (final batch).")

    print(f"[index] DONE dataset={dataset.key} | indexed={total} | deduped_ids={dup_count}")
    if skipped_empty_text:
        print(f"[index] Skipped {skipped_empty_text} chunks with empty text.")
    if empty_meta_fixed:
        print(f"[index] Fixed {empty_meta_fixed} chunks that had empty metadata.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    target = os.getenv("MITRE_INDEX_TARGET", "mitre")
    drop_existing = _parse_bool_env("MITRE_REINDEX_DROP", default=True)

    datasets = _select_datasets(target)

    # 1) Prepare embedding function
    embed_fn = get_embedding_function()

    # 2) Connect to Chroma
    print(f"[index] Connecting to Chroma at {DB_DIR} ...")
    DB_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(DB_DIR))

    # 3) Index selected dataset(s)
    print(f"[index] Target={target!r} -> datasets={[d.key for d in datasets]} | drop_existing={drop_existing}")
    for ds in datasets:
        _index_dataset(client=client, dataset=ds, embed_fn=embed_fn, drop_existing=drop_existing)


if __name__ == "__main__":
    main()
