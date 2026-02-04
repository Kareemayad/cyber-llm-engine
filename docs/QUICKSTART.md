# Quick Start Guide

This guide helps you get the Cyber LLM Engine running in minutes.

## Prerequisites

- Python 3.10+
- 8GB+ RAM (16GB recommended)
- GPU with 4GB+ VRAM (optional, for faster inference)

## Installation

### 1. Clone and Setup

```bash
git clone <repository-url>
cd cyber-llm-engine
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Download Models

Download the BGE-M3 embedding model and reranker:

```bash
# Create models directory
mkdir -p models

# Option A: Using huggingface-cli
pip install huggingface_hub
huggingface-cli download BAAI/bge-m3 --local-dir models/bge-m3
huggingface-cli download BAAI/bge-reranker-v2-m3 --local-dir models/bge-reranker-v2-m3

# Option B: Using Python
python -c "
from huggingface_hub import snapshot_download
snapshot_download('BAAI/bge-m3', local_dir='models/bge-m3')
snapshot_download('BAAI/bge-reranker-v2-m3', local_dir='models/bge-reranker-v2-m3')
"
```

### 3. Build Knowledge Packs

```bash
# Build MITRE ATT&CK knowledge pack
python -m mitre_expert.knowledge_pack.build_knowledge_pack

# Build D3FEND knowledge pack (optional)
python -m mitre_expert.knowledge_pack.build_d3fend
```

### 4. Index to ChromaDB

```bash
# Index MITRE chunks
python -m mitre_expert.rag.index_chroma --dataset mitre

# Index D3FEND chunks (optional)
python -m mitre_expert.rag.index_chroma --dataset d3fend
```

### 5. Test the RAG Pipeline

```bash
# Simple search
python -m mitre_expert.rag.query_chroma "powershell" --dataset mitre -k 5 --mode search -v

# Smart search (intent-aware)
python -m mitre_expert.rag.query_chroma "how to detect lateral movement" --dataset mitre -k 8 --mode smart -v
```

## Running the API

### Start the Server

```bash
# Development
uvicorn mitre_expert.api.main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn mitre_expert.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Test Endpoints

```bash
# Health check
curl http://localhost:8000/health

# DocQA query
curl -X POST http://localhost:8000/docqa \
  -H "Content-Type: application/json" \
  -d '{"question": "What is T1059.001?", "dataset": "mitre"}'

# Detection query
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"technique_id": "T1059.001"}'

# Mapper query
curl -X POST http://localhost:8000/mapper \
  -H "Content-Type: application/json" \
  -d '{"text": "PowerShell downloading script from internet"}'
```

## Configuration

Create a `.env` file for configuration:

```bash
# Embedding backend
MITRE_EMBED_BACKEND=bge-m3
MITRE_BGE_M3_MODEL_PATH=./models/bge-m3
MITRE_BGE_RERANKER_MODEL_PATH=./models/bge-reranker-v2-m3

# RAG settings
MITRE_RERANK_ENABLED=true
MITRE_ENABLE_MMR=true
MITRE_ENABLE_DIVERSIFICATION=true
MITRE_MIN_SEMANTIC_SIMILARITY=0.60

# LLM settings (optional)
MITRE_LLM_ENDPOINT=http://localhost:1234/v1
MITRE_LLM_MODEL=local-model
```

## Common Operations

### Search Commands

```bash
# Basic search
python -m mitre_expert.rag.query_chroma "query" --dataset mitre -k 5

# Filter by technique
python -m mitre_expert.rag.query_chroma "query" --tech T1059.001

# Filter by section
python -m mitre_expert.rag.query_chroma "query" --section detection_strategy

# Filter by tactic
python -m mitre_expert.rag.query_chroma "query" --tactic TA0002
```

### Search Modes

| Mode | Description |
|------|-------------|
| `search` | Standard semantic search |
| `smart` | Intent-aware with query analysis |
| `enhanced` | Full pipeline (hybrid + rerank + diversify + MMR) |

## Troubleshooting

### Model Loading Errors

```bash
# Check model path
ls -la models/bge-m3/
ls -la models/bge-reranker-v2-m3/

# Verify model files exist
python -c "from FlagEmbedding import BGEM3FlagModel; print('OK')"
```

### Memory Issues

```bash
# Use CPU if GPU memory insufficient
export MITRE_DEVICE=cpu

# Disable reranking to reduce memory
export MITRE_RERANK_ENABLED=false
```

### ChromaDB Issues

```bash
# Reset database
rm -rf data/embeddings/*/chroma

# Re-index
python -m mitre_expert.rag.index_chroma --dataset mitre
```

## Next Steps

1. Read [RAG Pipeline](RAG_PIPELINE.md) for advanced retrieval configuration
2. Review [API Reference](API_REFERENCE.md) for all endpoints
3. See [Configuration](CONFIGURATION.md) for all environment variables
4. Check [Architecture](ARCHITECTURE_MITRE_V1.md) for system design details
