# RAG Pipeline Documentation

## Overview

The Cyber LLM Engine uses an advanced Retrieval-Augmented Generation (RAG) pipeline to provide accurate, grounded answers. This document details the retrieval pipeline architecture and its components.

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         RAG PIPELINE (V2)                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  User Query                                                             │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  1. QUERY ANALYSIS                  │                               │
│  │  • Intent classification            │                               │
│  │  • Technique ID detection           │                               │
│  │  • Tactic detection                 │                               │
│  │  • Section inference                │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  2. QUERY EXPANSION                 │                               │
│  │  • MITRE-specific synonyms          │                               │
│  │  • Tactic term expansion            │                               │
│  │  • Intent-aware keywords            │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  3. SEMANTIC SEARCH                 │                               │
│  │  • BGE-M3 embeddings (1024-dim)     │                               │
│  │  • ChromaDB vector search           │                               │
│  │  • Metadata filtering               │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  4. HYBRID SEARCH (Optional)        │                               │
│  │  • BM25 keyword matching            │                               │
│  │  • RRF score fusion                 │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  5. QUALITY FILTERING               │                               │
│  │  • Minimum similarity threshold     │                               │
│  │  • Low-quality result removal       │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  6. RERANKING                       │                               │
│  │  • BGE-Reranker-v2-M3               │                               │
│  │  • Cross-encoder scoring            │                               │
│  │  • Score normalization              │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  7. DIVERSIFICATION                 │                               │
│  │  • Technique diversity (max 2/tech) │                               │
│  │  • Section diversity (max 3/type)   │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  ┌─────────────────────────────────────┐                               │
│  │  8. MMR SELECTION                   │                               │
│  │  • Relevance vs diversity balance   │                               │
│  │  • Final top-k selection            │                               │
│  └─────────────────────────────────────┘                               │
│      ↓                                                                  │
│  Retrieved Context (top-k chunks)                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Query Analysis

The system analyzes incoming queries to understand intent and extract entities.

**Intent Classification:**

| Intent | Detection Keywords | Retrieved Sections |
|--------|-------------------|-------------------|
| `DETECTION` | detect, hunt, monitor, alert | detection_strategy |
| `MITIGATION` | prevent, block, defend, protect | mitigation |
| `PROCEDURE` | example, how do, real-world | procedure_example |
| `DEFINITION` | what is, explain, describe | description |
| `DEFENSE` | d3fend, countermeasure | D3FEND dataset |
| `TECHNIQUE_SPECIFIC` | T1059, T1110, etc. | technique-filtered |
| `TACTIC_BROAD` | lateral movement, execution | tactic key techniques |

**Entity Extraction:**

```python
# Technique ID detection
pattern = r'\bT\d{4}(?:\.\d{3})?\b'  # T1059, T1059.001

# Tactic detection
# "lateral movement" → TA0008
# "credential access" → TA0006
```

### 2. Query Expansion

Expands queries with MITRE-specific synonyms to improve recall.

**Synonym Mappings:**

```python
MITRE_SYNONYMS = {
    "powershell": ["T1059.001", "command scripting interpreter", "pwsh"],
    "mimikatz": ["T1003", "credential dumping", "LSASS", "sekurlsa"],
    "credential": ["T1003", "password", "hash", "NTLM", "Kerberos"],
    "rdp": ["T1021.001", "remote desktop", "mstsc"],
    "psexec": ["T1021.002", "T1569.002", "remote service"],
    ...
}
```

**Tactic Expansions:**

```python
TACTIC_EXPANSIONS = {
    "lateral movement": [
        "T1021", "T1570", "remote services", "SMB", "RDP", "WinRM",
        "pass the hash", "pass the ticket", "psexec"
    ],
    "credential access": [
        "T1003", "T1558", "credential dumping", "LSASS", "mimikatz",
        "kerberoasting", "DCSync"
    ],
    ...
}
```

### 3. BGE-M3 Embeddings

State-of-the-art multilingual embedding model.

**Model Specifications:**

| Property | Value |
|----------|-------|
| Model | BAAI/bge-m3 |
| Dimensions | 1024 |
| Max Length | 8192 tokens |
| Supports | Dense, Sparse, ColBERT |

**Usage:**

```python
from FlagEmbedding import BGEM3FlagModel

model = BGEM3FlagModel(
    "models/bge-m3",
    use_fp16=True,  # GPU acceleration
    device="cuda",  # or "mps" for Mac
)

# Get embeddings
result = model.encode(
    texts,
    return_dense=True,
    return_sparse=False,
    return_colbert_vecs=False,
)
embeddings = result['dense_vecs']
```

**Why BGE-M3?**

- Better semantic understanding than smaller models
- Trained on diverse cybersecurity-related content
- Supports long documents (8192 tokens)
- Multilingual capability for international threat intelligence

### 4. Hybrid Search

Combines semantic search with keyword matching for better recall.

**BM25 Component:**

- Traditional keyword matching
- Catches exact terminology matches
- Important for technical terms (T1059, EventID 4624)

**Reciprocal Rank Fusion (RRF):**

```python
def rrf_score(rank, k=60):
    return 1.0 / (k + rank)

# Combine scores
final_score = semantic_weight * rrf_semantic + bm25_weight * rrf_bm25
# Default: 60% semantic, 40% BM25
```

**Configuration:**

```bash
export MITRE_HYBRID_ENABLED=true
```

### 5. Quality Filtering

Removes low-quality results before reranking.

**Similarity Threshold:**

```python
MIN_SEMANTIC_SIMILARITY = 0.60  # Default

# Results below this threshold are filtered out
# Prevents irrelevant chunks from reaching the LLM
```

**Auto-Detection:**

The system automatically detects whether distances are:
- Similarity scores (0-1, higher=better)
- Distance scores (0-2, lower=better)

### 6. BGE-Reranker-v2-M3

High-quality cross-encoder for precise reranking.

**Model Specifications:**

| Property | Value |
|----------|-------|
| Model | BAAI/bge-reranker-v2-m3 |
| Type | Cross-encoder |
| Max Length | 512 tokens |
| Output | Relevance score (0-1) |

**How It Works:**

```python
from FlagEmbedding import FlagReranker

reranker = FlagReranker(
    "models/bge-reranker-v2-m3",
    use_fp16=True,
    device="cuda",
)

# Score query-document pairs
pairs = [[query, doc] for doc in documents]
scores = reranker.compute_score(pairs, normalize=True)
```

**Why Cross-Encoder Reranking?**

- Bi-encoders (embeddings) are fast but approximate
- Cross-encoders see query+doc together for precise scoring
- Significantly improves precision@k

### 7. Diversification

Ensures variety in retrieved results.

**Technique Diversification:**

```python
MAX_RESULTS_PER_TECHNIQUE = 2  # Default

# Prevents all results from same technique
# Improves coverage across related techniques
```

**Section Diversification:**

```python
MAX_RESULTS_PER_SECTION = 3  # Default

# Ensures mix of:
# - detection_strategy
# - mitigation
# - procedure_example
# - description
```

**Example Before/After:**

| Before Diversification | After Diversification |
|----------------------|---------------------|
| T1047 procedure_example | T1047 procedure_example |
| T1047 procedure_example | T1047 detection_strategy |
| T1047 procedure_example | T1059 description |
| T1047 procedure_example | T1059 procedure_example |
| T1059 description | T1047 mitigation |

### 8. MMR (Maximum Marginal Relevance)

Final selection balancing relevance and diversity.

**Algorithm:**

```
MMR(d) = λ * Relevance(d, query) - (1-λ) * max(Similarity(d, selected))
```

**Parameters:**

| λ Value | Behavior |
|---------|----------|
| 1.0 | Pure relevance (no diversity) |
| 0.7 | Balanced toward relevance (default) |
| 0.5 | Equal relevance and diversity |
| 0.0 | Pure diversity (no relevance) |

**Configuration:**

```bash
export MITRE_MMR_LAMBDA=0.7
export MITRE_ENABLE_MMR=true
```

## Search Functions

### `search_chunks()` - Standard Search

```python
from mitre_expert.rag.query_chroma import search_chunks

results = search_chunks(
    dataset="mitre",           # or "d3fend", "all"
    query="How to detect T1059",
    k=8,                       # Top-k results
    where={"technique_id": "T1059"},  # Optional filter
    use_rerank=True,           # Enable reranking
    use_mmr=True,              # Enable MMR
    use_diversification=True,  # Enable diversification
)
```

### `search_chunks_smart()` - Intent-Aware Search

```python
from mitre_expert.rag.query_chroma import search_chunks_smart

results = search_chunks_smart(
    query="How do I detect lateral movement?",
    dataset="mitre",
    k=8,
)

# Automatically:
# - Classifies intent (DETECTION + TACTIC_BROAD)
# - Detects tactic (TA0008)
# - Expands query
# - Routes to appropriate search strategy
```

### `search_chunks_enhanced()` - Full Pipeline

```python
from mitre_expert.rag.query_chroma import search_chunks_enhanced

results = search_chunks_enhanced(
    dataset="mitre",
    query="credential dumping detection",
    k=8,
)

# Full pipeline:
# Hybrid search → Quality filter → Rerank → Diversify → MMR
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_EMBED_BACKEND` | `bge-m3` | Embedding backend |
| `MITRE_BGE_M3_MODEL_PATH` | `models/bge-m3` | BGE-M3 model path |
| `MITRE_BGE_RERANKER_MODEL_PATH` | `models/bge-reranker-v2-m3` | Reranker path |
| `MITRE_HYBRID_ENABLED` | `true` | Enable hybrid search |
| `MITRE_RERANK_ENABLED` | `true` | Enable reranking |
| `MITRE_ENABLE_MMR` | `true` | Enable MMR |
| `MITRE_ENABLE_DIVERSIFICATION` | `true` | Enable diversification |
| `MITRE_MIN_SEMANTIC_SIMILARITY` | `0.60` | Minimum similarity |
| `MITRE_MAX_PER_TECHNIQUE` | `2` | Max results per technique |
| `MITRE_MAX_PER_SECTION` | `3` | Max results per section |
| `MITRE_MMR_LAMBDA` | `0.7` | MMR relevance/diversity balance |
| `MITRE_PREFETCH_K` | `100` | Prefetch pool size |

## Performance Considerations

### Memory Requirements

| Component | Memory |
|-----------|--------|
| BGE-M3 (FP16) | ~2GB |
| BGE-Reranker (FP16) | ~1GB |
| ChromaDB (50k chunks) | ~500MB |
| Total | ~4GB GPU |

### Latency Breakdown

| Stage | Typical Time |
|-------|-------------|
| Query analysis | <10ms |
| Embedding | ~50ms |
| ChromaDB search | ~20ms |
| Reranking (100 docs) | ~200ms |
| Diversification | <10ms |
| MMR | ~50ms |
| **Total** | ~350ms |

### Optimization Tips

1. **GPU Acceleration**: Use CUDA or MPS for embeddings/reranking
2. **Batch Processing**: Reuse embedding function (singleton)
3. **Prefetch Tuning**: Adjust `PREFETCH_K` based on collection size
4. **Disable Features**: Turn off MMR/diversification if latency critical

## Troubleshooting

### Low Relevance Results

1. Check embedding model is loaded correctly
2. Verify chunks are indexed with correct embeddings
3. Lower `MIN_SEMANTIC_SIMILARITY` threshold
4. Enable hybrid search for keyword matching

### Too Similar Results

1. Enable diversification
2. Enable MMR with lower lambda (0.5)
3. Increase `MAX_RESULTS_PER_TECHNIQUE`

### Missing Expected Results

1. Enable query expansion
2. Check metadata filters aren't too restrictive
3. Increase `k` parameter
4. Verify chunks exist in collection

### Slow Performance

1. Use GPU (CUDA/MPS) for models
2. Reduce `PREFETCH_K`
3. Disable unused features (MMR, hybrid)
4. Use smaller reranker model
