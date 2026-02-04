# Configuration Guide

Complete reference for all configuration options in the Cyber LLM Engine.

## Configuration Methods

Configuration can be set via:

1. **Environment variables** (recommended for deployment)
2. **Config file** (`src/mitre_expert/config.py`)
3. **API parameters** (per-request overrides)

## Environment Variables

### Embedding Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_EMBED_BACKEND` | `bge-m3` | Embedding backend: `bge-m3`, `lmstudio`, `hf`, `ollama` |
| `MITRE_BGE_M3_MODEL_PATH` | `{REPO_ROOT}/models/bge-m3` | Path to BGE-M3 model |
| `MITRE_BGE_RERANKER_MODEL_PATH` | `{REPO_ROOT}/models/bge-reranker-v2-m3` | Path to reranker model |
| `MITRE_LMSTUDIO_BASE_URL` | `http://localhost:1234/v1` | LM Studio server URL |
| `MITRE_LMSTUDIO_EMBED_MODEL` | `text-embedding-bge-large-en-v1.5` | LM Studio model name |
| `MITRE_HF_EMBED_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | HuggingFace model |
| `MITRE_OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Ollama embedding model |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |

### Retrieval Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_DEFAULT_TOPK` | `8` | Default number of chunks to retrieve |
| `MITRE_PREFETCH_K` | `100` | Prefetch pool size for reranking |
| `MITRE_GET_HARD_CAP` | `500` | Hard cap for deterministic queries |

### Quality Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_MIN_SEMANTIC_SIMILARITY` | `0.60` | Minimum similarity threshold (0.0-1.0) |
| `MITRE_MIN_RERANK_SCORE` | `-5.0` | Minimum reranker score (for strict mode) |
| `MITRE_MAX_PER_TECHNIQUE` | `2` | Maximum results per technique |
| `MITRE_MAX_PER_SECTION` | `3` | Maximum results per section type |
| `MITRE_MMR_LAMBDA` | `0.7` | MMR balance (0=diversity, 1=relevance) |

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_ENABLE_MMR` | `true` | Enable Maximum Marginal Relevance |
| `MITRE_ENABLE_DIVERSIFICATION` | `true` | Enable section/technique diversity |
| `MITRE_HYBRID_ENABLED` | `true` | Enable hybrid (BM25 + semantic) search |
| `MITRE_RERANK_ENABLED` | `true` | Enable cross-encoder reranking |
| `MITRE_QUERY_EXPANSION` | `true` | Enable query expansion |
| `MITRE_STRICT_MODE` | `false` | Enable strict validation |

### LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_LOCAL_LLM_MODEL` | `llama3.1:latest` | LLM model for answer generation |
| `MITRE_LOCAL_LLM_BASE_URL` | `{OLLAMA_BASE_URL}` | LLM server URL |
| `MITRE_DOCQA_TEMPERATURE` | `0.3` | Temperature for DocQA |
| `MITRE_DETECT_TEMPERATURE` | `0.2` | Temperature for Detect |
| `MITRE_MAPPER_TEMPERATURE` | `0.1` | Temperature for Mapper |

### Data Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_REPO_ROOT` | Auto-detected | Repository root directory |
| `MITRE_DATA_DIR` | `{REPO_ROOT}/data` | Data directory |
| `MITRE_CHROMA_DIR` | `{DATA_DIR}/embeddings/mitre/chroma` | ChromaDB directory |
| `MITRE_INDEX_TARGET` | `mitre` | Default indexing target |
| `MITRE_REINDEX_DROP` | `true` | Drop collection before reindexing |
| `MITRE_INDEX_BATCH_SIZE` | `64` | Batch size for indexing |

## Configuration Examples

### Development Setup

```bash
# Use local models
export MITRE_EMBED_BACKEND=bge-m3
export MITRE_BGE_M3_MODEL_PATH=/path/to/models/bge-m3
export MITRE_BGE_RERANKER_MODEL_PATH=/path/to/models/bge-reranker-v2-m3

# Enable all features
export MITRE_ENABLE_MMR=true
export MITRE_ENABLE_DIVERSIFICATION=true
export MITRE_HYBRID_ENABLED=true
export MITRE_RERANK_ENABLED=true

# LLM
export MITRE_LOCAL_LLM_MODEL=llama3.1:latest
export OLLAMA_BASE_URL=http://localhost:11434
```

### Production Setup (High Quality)

```bash
# Production embedding
export MITRE_EMBED_BACKEND=bge-m3

# Strict quality thresholds
export MITRE_MIN_SEMANTIC_SIMILARITY=0.65
export MITRE_STRICT_MODE=true

# All enhancements enabled
export MITRE_ENABLE_MMR=true
export MITRE_ENABLE_DIVERSIFICATION=true
export MITRE_HYBRID_ENABLED=true
export MITRE_RERANK_ENABLED=true

# Higher prefetch for better reranking
export MITRE_PREFETCH_K=150
```

### Low-Resource Setup

```bash
# Use lighter embedding model
export MITRE_EMBED_BACKEND=hf
export MITRE_HF_EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2

# Disable expensive features
export MITRE_RERANK_ENABLED=false
export MITRE_ENABLE_MMR=false
export MITRE_HYBRID_ENABLED=false

# Lower prefetch
export MITRE_PREFETCH_K=30
```

### LM Studio Setup

```bash
# Use LM Studio for embeddings
export MITRE_EMBED_BACKEND=lmstudio
export MITRE_LMSTUDIO_BASE_URL=http://localhost:1234/v1
export MITRE_LMSTUDIO_EMBED_MODEL=text-embedding-bge-large-en-v1.5

# Disable local reranking (LM Studio doesn't support it)
export MITRE_RERANK_ENABLED=false
```

### Ollama-Only Setup

```bash
# Use Ollama for embeddings
export MITRE_EMBED_BACKEND=ollama
export MITRE_OLLAMA_EMBED_MODEL=nomic-embed-text
export OLLAMA_BASE_URL=http://localhost:11434

# LLM
export MITRE_LOCAL_LLM_MODEL=llama3.1:latest
```

## Feature Configuration Details

### Embedding Backends

**BGE-M3 (Recommended)**
```bash
export MITRE_EMBED_BACKEND=bge-m3
export MITRE_BGE_M3_MODEL_PATH=/path/to/bge-m3
```
- Best quality embeddings
- 1024 dimensions
- Requires FlagEmbedding library
- ~2GB GPU memory

**LM Studio**
```bash
export MITRE_EMBED_BACKEND=lmstudio
export MITRE_LMSTUDIO_BASE_URL=http://localhost:1234/v1
export MITRE_LMSTUDIO_EMBED_MODEL=text-embedding-bge-large-en-v1.5
```
- Uses LM Studio's OpenAI-compatible API
- Good for Mac users
- Limited to encoder-only models

**HuggingFace**
```bash
export MITRE_EMBED_BACKEND=hf
export MITRE_HF_EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2
```
- Uses sentence-transformers library
- Many model options
- Runs on CPU/GPU/MPS

**Ollama**
```bash
export MITRE_EMBED_BACKEND=ollama
export MITRE_OLLAMA_EMBED_MODEL=nomic-embed-text
```
- Uses Ollama's embedding API
- Easy setup with Ollama
- Limited model selection

### Reranking Configuration

**BGE-Reranker (Best)**
```bash
export MITRE_RERANK_ENABLED=true
export MITRE_BGE_RERANKER_MODEL_PATH=/path/to/bge-reranker-v2-m3
```

**Fallback to CrossEncoder**

If FlagEmbedding not available, falls back to:
```python
CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
```

**Disable Reranking**
```bash
export MITRE_RERANK_ENABLED=false
```

### MMR Configuration

```bash
# Enable MMR
export MITRE_ENABLE_MMR=true

# Lambda parameter
export MITRE_MMR_LAMBDA=0.7  # 0.0-1.0
# 1.0 = pure relevance
# 0.0 = pure diversity
# 0.7 = balanced toward relevance (recommended)
```

### Diversification Configuration

```bash
# Enable diversification
export MITRE_ENABLE_DIVERSIFICATION=true

# Technique diversity
export MITRE_MAX_PER_TECHNIQUE=2

# Section diversity
export MITRE_MAX_PER_SECTION=3
```

### Hybrid Search Configuration

```bash
# Enable hybrid search
export MITRE_HYBRID_ENABLED=true
```

Requires `rank-bm25` package:
```bash
pip install rank-bm25
```

## Validation

Check current configuration:

```bash
python -m mitre_expert.config --validate
```

Output:
```
============================================================
MITRE Expert Configuration
============================================================

Repository:
  REPO_ROOT: /path/to/cyber-llm-engine
  DATA_DIR:  /path/to/cyber-llm-engine/data

ChromaDB:
  CHROMA_DB_DIR: /path/to/cyber-llm-engine/data/embeddings/mitre/chroma
  Collections:   mitre_chunks_v1, d3fend_chunks_v1

Embeddings:
  Backend: bge-m3
  Model:     /path/to/models/bge-m3
  Reranker:  /path/to/models/bge-reranker-v2-m3

Query Settings:
  Default top-k: 8
  Prefetch k:    100
  Get hard cap:  500

Retrieval Quality:
  Min similarity:      0.6
  Min rerank score:    -5.0
  Max per technique:   2
  Max per section:     3
  MMR lambda:          0.7

Feature Flags:
  MMR:             ✓
  Diversification: ✓
  Hybrid search:   ✓
  Reranking:       ✓

Path Validation:
  ✓ REPO_ROOT
  ✓ DATA_DIR
  ✓ DATA_PROCESSED_MITRE_DIR
  ✓ CHROMA_DB_DIR
============================================================
```

## Troubleshooting

### "Unknown EMBED_BACKEND"

Ensure valid backend name:
```bash
export MITRE_EMBED_BACKEND=bge-m3  # Not "bge_m3" or "BGE-M3"
```

### "Model not found"

Check model path exists:
```bash
ls -la $MITRE_BGE_M3_MODEL_PATH
```

### "FlagEmbedding not installed"

Install the library:
```bash
pip install FlagEmbedding
```

### "ChromaDB connection error"

Ensure ChromaDB directory exists:
```bash
mkdir -p data/embeddings/mitre/chroma
```

### "Reranking disabled"

Check reranker model path and FlagEmbedding installation:
```bash
pip install FlagEmbedding
ls -la $MITRE_BGE_RERANKER_MODEL_PATH
```
