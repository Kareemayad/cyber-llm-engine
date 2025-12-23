# src/mitre_expert/config.py

from pathlib import Path

# This file sits at: src/mitre_expert/config.py
# repo_root = .../cyber-llm-engine
REPO_ROOT = Path(__file__).resolve().parents[2]

DATA_PROCESSED_MITRE = REPO_ROOT / "data" / "processed" / "mitre"
EMBEDDINGS_MITRE_DIR = REPO_ROOT / "data" / "embeddings" / "mitre" / "chroma"

MITRE_KNOWLEDGE_PACK_PATH = DATA_PROCESSED_MITRE / "mitre_knowledge_pack_v1.jsonl"
MITRE_CHUNKS_PATH = DATA_PROCESSED_MITRE / "mitre_chunks_v1.jsonl"

MITRE_CHROMA_COLLECTION = "mitre_chunks_v1"
