# Cyber LLM Engine - MITRE Expert Layer

An AI-powered cybersecurity assistant for SOC teams, providing intelligent MITRE ATT&CK and D3FEND knowledge through a local, self-hosted system.

## Overview

The Cyber LLM Engine transforms MITRE ATT&CK and D3FEND knowledge into an intelligent, conversational cybersecurity assistant. It combines:

- **Retrieval-Augmented Generation (RAG)** with state-of-the-art embeddings
- **Local Large Language Models** for privacy and control
- **Advanced retrieval techniques** (BGE-M3, reranking, MMR, hybrid search)
- **Zero hallucination design** - all answers grounded in trusted datasets

## Key Features

| Feature | Description |
|---------|-------------|
| **MITRE DocQA** | Answer questions about techniques, tactics, mitigations |
| **MITRE Mapper** | Map logs, alerts, or CTI text to ATT&CK techniques |
| **MITRE Detect** | Get detection guidance for specific techniques |
| **D3FEND DocQA** | Answer defensive/countermeasure questions |
| **Chat Interface** | Conversational experience with memory and context tracking |
| **OpenAI-Compatible API** | Connect with Open WebUI and other tools |

## Architecture

```
User Query
    ↓
┌─────────────────────────────────────┐
│  Smart Router                       │
│  (Intent Detection)                 │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Enhanced RAG Layer                 │
│  • BGE-M3 Embeddings (1024-dim)     │
│  • Hybrid Search (BM25 + Semantic)  │
│  • BGE-Reranker-v2-M3               │
│  • MMR Diversification              │
│  • Section/Technique Diversity      │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Local LLM Layer                    │
│  (Ollama / MLX / Transformers)      │
└─────────────────────────────────────┘
    ↓
Structured, Grounded Response
```

## Quick Start

### Prerequisites

- Python 3.10+
- 16GB+ RAM (for BGE-M3 models)
- Ollama (for LLM inference)

### Installation

```bash
# Clone the repository
git clone https://github.com/Kareemayad/cyber-llm-engine.git
cd cyber-llm-engine

# Install dependencies
pip install -e .

# Install FlagEmbedding for BGE-M3 support
pip install FlagEmbedding

# Download BGE-M3 models (place in models/ directory)
# - models/bge-m3
# - models/bge-reranker-v2-m3
```

### Index the Knowledge Base

```bash
# Index MITRE ATT&CK chunks
python -m mitre_expert.rag.index_chroma --target mitre

# Index D3FEND chunks
python -m mitre_expert.rag.index_chroma --target d3fend

# Or index both
python -m mitre_expert.rag.index_chroma --target all
```

### Start the API Server

```bash
# Start Ollama (in separate terminal)
ollama run llama3.1:latest

# Start the API server
uvicorn mitre_expert.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Test the API

```bash
# DocQA - Ask about a technique
curl -X POST http://localhost:8000/docqa \
  -H "Content-Type: application/json" \
  -d '{"question": "What is T1059 and how do attackers use it?"}'

# Detect - Get detection guidance
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"technique_id": "T1059", "available_logs": ["Sysmon", "Windows Security"]}'

# Mapper - Map logs to techniques
curl -X POST http://localhost:8000/mapper \
  -H "Content-Type: application/json" \
  -d '{"text": "Multiple failed login attempts followed by success from same IP"}'

# Chat - Conversational interface
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is T1059?"}'
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Health check |
| `/docs` | GET | OpenAPI documentation |
| `/docqa` | POST | MITRE ATT&CK Q&A |
| `/detect` | POST | Detection guidance |
| `/mapper` | POST | Log-to-technique mapping |
| `/d3fend/docqa` | POST | D3FEND defensive guidance |
| `/chat` | POST | Conversational chat with memory |
| `/query` | POST | Smart router (auto-selects endpoint) |
| `/v1/chat/completions` | POST | OpenAI-compatible API |

## Configuration

### Environment Variables

```bash
# Embedding Backend (default: bge-m3)
export MITRE_EMBED_BACKEND=bge-m3

# Model Paths
export MITRE_BGE_M3_MODEL_PATH=/path/to/models/bge-m3
export MITRE_BGE_RERANKER_MODEL_PATH=/path/to/models/bge-reranker-v2-m3

# Feature Flags
export MITRE_ENABLE_MMR=true
export MITRE_ENABLE_DIVERSIFICATION=true
export MITRE_HYBRID_ENABLED=true
export MITRE_RERANK_ENABLED=true

# Quality Thresholds
export MITRE_MIN_SEMANTIC_SIMILARITY=0.60
export MITRE_MAX_PER_TECHNIQUE=2
export MITRE_MAX_PER_SECTION=3
export MITRE_MMR_LAMBDA=0.7

# LLM Settings
export MITRE_LOCAL_LLM_MODEL=llama3.1:latest
export OLLAMA_BASE_URL=http://localhost:11434
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for complete configuration reference.

## Project Structure

```
cyber-llm-engine/
├── src/mitre_expert/
│   ├── api/                    # FastAPI endpoints
│   │   ├── main.py            # App entry point
│   │   ├── routers/           # API routers
│   │   └── openai_compat.py   # OpenAI-compatible endpoint
│   ├── chat/                   # Chat module
│   │   ├── session.py         # Session management
│   │   └── coreference.py     # Pronoun resolution
│   ├── knowledge_pack/         # Data processing
│   │   ├── build_knowledge_pack.py
│   │   ├── build_chunks.py
│   │   └── build_d3fend.py
│   ├── llm/                    # LLM integration
│   │   ├── local_llm.py       # Model backends
│   │   ├── prompts.py         # System prompts
│   │   ├── mitre_docqa.py
│   │   ├── mitre_detect.py
│   │   ├── mitre_mapper.py
│   │   └── d3fend_docqa.py
│   ├── models/                 # Data models
│   │   ├── technique.py
│   │   ├── enums.py
│   │   └── technique_resolver.py
│   └── rag/                    # RAG layer
│       ├── query_chroma.py    # Enhanced search
│       └── index_chroma.py    # Indexing
├── models/                     # Local ML models
│   ├── bge-m3/
│   └── bge-reranker-v2-m3/
├── data/
│   ├── raw/                   # Raw MITRE data
│   ├── processed/             # Knowledge packs & chunks
│   └── embeddings/            # ChromaDB vector store
├── docs/                       # Documentation
└── chat-ui.html               # Web chat interface
```

## Documentation

- [Architecture Overview](docs/ARCHITECTURE_MITRE_V1.md)
- [RAG Pipeline](docs/RAG_PIPELINE.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [API Reference](docs/API_REFERENCE.md)
- [MITRE Knowledge Pack](docs/DATA_MITRE_KNOWLEDGE_PACK.md)
- [D3FEND Knowledge Pack](docs/DATA_D3FEND_KNOWLEDGE_PACK.md)
- [Roadmap](docs/ROADMAP.md)

## RAG Enhancements (v2)

The latest version includes significant RAG improvements:

### BGE-M3 Embeddings
- State-of-the-art multilingual embeddings (1024 dimensions)
- Supports dense, sparse, and ColBERT representations
- Better semantic understanding of cybersecurity concepts

### BGE-Reranker-v2-M3
- High-quality cross-encoder reranking
- Significantly improves retrieval precision
- Normalizes scores for consistent ranking

### MMR (Maximum Marginal Relevance)
- Balances relevance with diversity
- Prevents redundant results
- Configurable lambda parameter (0.7 default)

### Diversification
- Limits results per technique (max 2 by default)
- Limits results per section type (max 3 by default)
- Ensures variety in detection, mitigation, procedures

### Hybrid Search
- Combines BM25 keyword matching + semantic search
- RRF (Reciprocal Rank Fusion) for score combination
- Catches exact matches that pure semantic might miss

## Web UI

Open `chat-ui.html` in a browser for a chat interface, or visit `/docs` for the interactive API documentation.

## Design Principles

1. **Zero Hallucination Tolerance** - All answers grounded in MITRE data
2. **Dataset-Grounded Intelligence** - No external knowledge beyond context
3. **SOC-First Usability** - Designed for SOC Analysts (L1-L3)
4. **Modular & Extensible** - Each capability is independent and replaceable
5. **Privacy-First** - Runs entirely locally, no external API calls

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

[Add your license here]

## Acknowledgments

- MITRE ATT&CK - https://attack.mitre.org/
- MITRE D3FEND - https://d3fend.mitre.org/
- BGE-M3 - https://github.com/FlagOpen/FlagEmbedding
