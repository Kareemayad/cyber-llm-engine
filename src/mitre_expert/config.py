# src/mitre_expert/config.py
"""
Central configuration for MITRE Expert.

All paths and constants should be imported from here to ensure consistency.

Usage:
    from mitre_expert.config import (
        REPO_ROOT,
        MITRE_CHUNKS_PATH,
        D3FEND_CHUNKS_PATH,
        CHROMA_DB_DIR,
    )

Environment variable overrides:
    MITRE_REPO_ROOT          - Override repository root
    MITRE_DATA_DIR           - Override data directory
    MITRE_CHROMA_DIR         - Override ChromaDB directory
    MITRE_EMBED_BACKEND      - Embedding backend: "lmstudio" (default), "hf", or "ollama"
    MITRE_LMSTUDIO_BASE_URL  - LM Studio server URL (default: http://localhost:1234/v1)
    MITRE_LMSTUDIO_EMBED_MODEL - LM Studio model name (default: gte-Qwen2-7B-instruct)
    MITRE_HF_EMBED_MODEL     - HuggingFace model name
    MITRE_OLLAMA_EMBED_MODEL - Ollama model name
    OLLAMA_BASE_URL          - Ollama server URL
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Repository root detection
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    """
    Find repository root by looking for marker files.
    
    More robust than hardcoded parents[N] - works even if this file moves.
    """
    # Check environment override first
    env_root = os.getenv("MITRE_REPO_ROOT")
    if env_root:
        return Path(env_root).resolve()
    
    # Search upward for marker files
    current = Path(__file__).resolve().parent
    markers = ["pyproject.toml", "setup.py", ".git", "requirements.txt"]
    
    for _ in range(10):  # Max depth to search
        if any((current / marker).exists() for marker in markers):
            return current
        if current.parent == current:
            break
        current = current.parent
    
    # Fallback: assume standard layout (src/mitre_expert/config.py)
    return Path(__file__).resolve().parents[2]


REPO_ROOT = _find_repo_root()


# ---------------------------------------------------------------------------
# Data directories
# ---------------------------------------------------------------------------

def _get_data_dir() -> Path:
    """Get data directory, with environment override support."""
    env_data = os.getenv("MITRE_DATA_DIR")
    if env_data:
        return Path(env_data).resolve()
    return REPO_ROOT / "data"


DATA_DIR = _get_data_dir()

# Raw data (input)
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_RAW_MITRE_DIR = DATA_RAW_DIR / "mitre"

# Processed data (intermediate)
DATA_PROCESSED_DIR = DATA_DIR / "processed"
DATA_PROCESSED_MITRE_DIR = DATA_PROCESSED_DIR / "mitre"

# Embeddings (ChromaDB)
DATA_EMBEDDINGS_DIR = DATA_DIR / "embeddings"
EMBEDDINGS_MITRE_DIR = DATA_EMBEDDINGS_DIR / "mitre"


# ---------------------------------------------------------------------------
# ChromaDB configuration
# ---------------------------------------------------------------------------

def _get_chroma_dir() -> Path:
    """Get ChromaDB directory, with environment override support."""
    env_chroma = os.getenv("MITRE_CHROMA_DIR")
    if env_chroma:
        return Path(env_chroma).resolve()
    return EMBEDDINGS_MITRE_DIR / "chroma"


CHROMA_DB_DIR = _get_chroma_dir()

# Collection names
MITRE_CHROMA_COLLECTION = "mitre_chunks_v1"
D3FEND_CHROMA_COLLECTION = "d3fend_chunks_v1"


# ---------------------------------------------------------------------------
# MITRE ATT&CK file paths
# ---------------------------------------------------------------------------

# Raw inputs
MITRE_RAW_TECHNIQUES_PATH = DATA_RAW_MITRE_DIR / "techniques_full.jsonl"
MITRE_RAW_STIX_PATH = DATA_RAW_MITRE_DIR / "enterprise-attack-18.1.json"
MITRE_RAW_TECHNIQUES_XLSX = DATA_RAW_MITRE_DIR / "enterprise-attack-v18.1-techniques.xlsx"
MITRE_RAW_DATACOMPONENTS_XLSX = DATA_RAW_MITRE_DIR / "enterprise-attack-v18.1-datacomponents.xlsx"

# Processed outputs
MITRE_TECHNIQUE_DC_MAP_PATH = DATA_PROCESSED_MITRE_DIR / "technique_data_components.csv"
MITRE_ENRICHED_TECHNIQUES_PATH = DATA_PROCESSED_MITRE_DIR / "techniques_full_enriched.jsonl"
MITRE_KNOWLEDGE_PACK_PATH = DATA_PROCESSED_MITRE_DIR / "mitre_knowledge_pack_v1.jsonl"
MITRE_CHUNKS_PATH = DATA_PROCESSED_MITRE_DIR / "mitre_chunks_v1.jsonl"


# ---------------------------------------------------------------------------
# D3FEND file paths
# ---------------------------------------------------------------------------

# Raw inputs
D3FEND_RAW_JSONLD_PATH = DATA_RAW_MITRE_DIR / "d3fend.json"
D3FEND_RAW_MAPPINGS_CSV_PATH = DATA_RAW_MITRE_DIR / "d3fend-full-mappings.csv"

# Processed outputs
D3FEND_NORMALIZED_JSON_PATH = DATA_PROCESSED_MITRE_DIR / "d3fend_normalized_v1.json"
D3FEND_DEFENSES_PATH = DATA_PROCESSED_MITRE_DIR / "d3fend_defenses_v1.jsonl"
D3FEND_CHUNKS_PATH = DATA_PROCESSED_MITRE_DIR / "d3fend_chunks_v1.jsonl"


# ---------------------------------------------------------------------------
# Embedding configuration
# ---------------------------------------------------------------------------

# Backend: "lmstudio" (default), "hf" (HuggingFace sentence-transformers), or "ollama"
EMBED_BACKEND = os.getenv("MITRE_EMBED_BACKEND", "lmstudio").lower()

# LM Studio configuration (default - using bge-large-en-v1.5)
# Encoder-only models that work: text-embedding-bge-large-en-v1.5, text-embedding-nomic-embed-text-v1.5
# LLM-based models (gte-Qwen2, e5-mistral) do NOT work with LM Studio's /v1/embeddings endpoint
LMSTUDIO_BASE_URL = os.getenv("MITRE_LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
LMSTUDIO_EMBED_MODEL = os.getenv("MITRE_LMSTUDIO_EMBED_MODEL", "text-embedding-bge-large-en-v1.5")

# HuggingFace model (fallback)
HF_EMBED_MODEL = os.getenv("MITRE_HF_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

# Ollama configuration (fallback)
OLLAMA_EMBED_MODEL = os.getenv("MITRE_OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


# ---------------------------------------------------------------------------
# Query/retrieval configuration
# ---------------------------------------------------------------------------

# Default number of chunks to retrieve
DEFAULT_TOPK = int(os.getenv("MITRE_DEFAULT_TOPK", "8"))

# Prefetch multiplier for post-filtering
PREFETCH_K = int(os.getenv("MITRE_PREFETCH_K", "50"))

# Hard cap for deterministic .get() queries
GET_HARD_CAP = int(os.getenv("MITRE_GET_HARD_CAP", "500"))


# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

# Local LLM model (for answer generation)
LOCAL_LLM_MODEL = os.getenv("MITRE_LOCAL_LLM_MODEL", "llama3.1:latest")
LOCAL_LLM_BASE_URL = os.getenv("MITRE_LOCAL_LLM_BASE_URL", OLLAMA_BASE_URL)

# Temperature defaults
DEFAULT_DOCQA_TEMPERATURE = float(os.getenv("MITRE_DOCQA_TEMPERATURE", "0.3"))
DEFAULT_DETECT_TEMPERATURE = float(os.getenv("MITRE_DETECT_TEMPERATURE", "0.2"))
DEFAULT_MAPPER_TEMPERATURE = float(os.getenv("MITRE_MAPPER_TEMPERATURE", "0.1"))


# ---------------------------------------------------------------------------
# Indexing configuration
# ---------------------------------------------------------------------------

# Batch size for ChromaDB inserts
INDEX_BATCH_SIZE = int(os.getenv("MITRE_INDEX_BATCH_SIZE", "64"))


# ---------------------------------------------------------------------------
# Dataset configurations (for index_chroma.py)
# ---------------------------------------------------------------------------

from dataclasses import dataclass
from typing import List as ListType


@dataclass(frozen=True)
class DatasetConfig:
    """Configuration for a dataset to index."""
    key: str
    chunks_path: Path
    collection_name: str


DATASETS: ListType[DatasetConfig] = [
    DatasetConfig(
        key="mitre",
        chunks_path=MITRE_CHUNKS_PATH,
        collection_name=MITRE_CHROMA_COLLECTION,
    ),
    DatasetConfig(
        key="d3fend",
        chunks_path=D3FEND_CHUNKS_PATH,
        collection_name=D3FEND_CHROMA_COLLECTION,
    ),
]


def get_dataset_config(key: str) -> Optional[DatasetConfig]:
    """Get dataset configuration by key."""
    for ds in DATASETS:
        if ds.key == key:
            return ds
    return None


def get_all_dataset_keys() -> List[str]:
    """Get list of all dataset keys."""
    return [ds.key for ds in DATASETS]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_paths(raise_on_missing: bool = False) -> dict:
    """
    Validate that expected paths exist.
    
    Returns dict of {path_name: exists_bool}.
    Optionally raises FileNotFoundError for missing critical paths.
    """
    paths_to_check = {
        "REPO_ROOT": REPO_ROOT,
        "DATA_DIR": DATA_DIR,
        "DATA_PROCESSED_MITRE_DIR": DATA_PROCESSED_MITRE_DIR,
        "CHROMA_DB_DIR": CHROMA_DB_DIR,
    }
    
    results = {}
    missing = []
    
    for name, path in paths_to_check.items():
        exists = path.exists()
        results[name] = exists
        if not exists:
            missing.append(f"{name}: {path}")
    
    if raise_on_missing and missing:
        raise FileNotFoundError(
            f"Missing required paths:\n" + "\n".join(f"  - {m}" for m in missing)
        )
    
    return results


def ensure_directories() -> None:
    """Create required directories if they don't exist."""
    dirs_to_create = [
        DATA_PROCESSED_MITRE_DIR,
        CHROMA_DB_DIR,
    ]
    
    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Debug/info helpers
# ---------------------------------------------------------------------------

def print_config() -> None:
    """Print current configuration for debugging."""
    print("=" * 60)
    print("MITRE Expert Configuration")
    print("=" * 60)
    print(f"\nRepository:")
    print(f"  REPO_ROOT: {REPO_ROOT}")
    print(f"  DATA_DIR:  {DATA_DIR}")
    
    print(f"\nChromaDB:")
    print(f"  CHROMA_DB_DIR: {CHROMA_DB_DIR}")
    print(f"  Collections:   {MITRE_CHROMA_COLLECTION}, {D3FEND_CHROMA_COLLECTION}")
    
    print(f"\nEmbeddings:")
    print(f"  Backend: {EMBED_BACKEND}")
    if EMBED_BACKEND == "lmstudio":
        print(f"  URL:     {LMSTUDIO_BASE_URL}")
        print(f"  Model:   {LMSTUDIO_EMBED_MODEL}")
    elif EMBED_BACKEND == "hf":
        print(f"  Model:   {HF_EMBED_MODEL}")
    else:
        print(f"  Model:   {OLLAMA_EMBED_MODEL}")
        print(f"  URL:     {OLLAMA_BASE_URL}")
    
    print(f"\nMITRE Paths:")
    print(f"  Knowledge Pack: {MITRE_KNOWLEDGE_PACK_PATH}")
    print(f"  Chunks:         {MITRE_CHUNKS_PATH}")
    print(f"  Enriched:       {MITRE_ENRICHED_TECHNIQUES_PATH}")
    
    print(f"\nD3FEND Paths:")
    print(f"  Defenses: {D3FEND_DEFENSES_PATH}")
    print(f"  Chunks:   {D3FEND_CHUNKS_PATH}")
    
    print(f"\nQuery Settings:")
    print(f"  Default top-k: {DEFAULT_TOPK}")
    print(f"  Prefetch k:    {PREFETCH_K}")
    print(f"  Get hard cap:  {GET_HARD_CAP}")
    
    print(f"\nPath Validation:")
    results = validate_paths()
    for name, exists in results.items():
        status = "✓" if exists else "✗"
        print(f"  {status} {name}")
    
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MITRE Expert configuration")
    parser.add_argument("--validate", action="store_true", help="Validate paths exist")
    parser.add_argument("--create-dirs", action="store_true", help="Create required directories")
    
    args = parser.parse_args()
    
    print_config()
    
    if args.validate:
        try:
            validate_paths(raise_on_missing=True)
            print("\n✓ All paths valid")
        except FileNotFoundError as e:
            print(f"\n✗ {e}")
            exit(1)
    
    if args.create_dirs:
        ensure_directories()
        print("\n✓ Directories created")