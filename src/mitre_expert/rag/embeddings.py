"""
Embedding function backends for RAG pipeline.

This module provides embedding functions for different backends:
- BGE-M3 (default, best quality)
- LM Studio (OpenAI-compatible API)
- Ollama (local models)
- HuggingFace sentence-transformers

All embedding functions implement the ChromaDB EmbeddingFunction interface.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import List

from chromadb.utils import embedding_functions

from mitre_expert.config import (
    EMBED_BACKEND,
    HF_EMBED_MODEL,
    OLLAMA_EMBED_MODEL,
    OLLAMA_BASE_URL,
    LMSTUDIO_BASE_URL,
    LMSTUDIO_EMBED_MODEL,
    BGE_M3_MODEL_PATH,
)

logger = logging.getLogger("mitre_expert.embeddings")


class LMStudioEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """Embedding function using LM Studio's OpenAI-compatible API."""

    def __init__(
        self,
        base_url: str = "http://localhost:1234/v1",
        model: str = "text-embedding-bge-large-en-v1.5",
        max_retries: int = 3,
        timeout: int = 120,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_retries = max_retries
        self.timeout = timeout
        self._embed_url = f"{self.base_url}/embeddings"
        self._session = None

    def _get_session(self):
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            self._session = requests.Session()
            retry_strategy = Retry(
                total=self.max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)

        return self._session

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []

        session = self._get_session()
        payload = {"input": input}
        if self.model:
            payload["model"] = self.model

        try:
            resp = session.post(
                self._embed_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            embeddings = []
            for item in sorted(data.get("data", []), key=lambda x: x.get("index", 0)):
                embeddings.append(item["embedding"])

            return embeddings

        except Exception as e:
            logger.error(f"LM Studio embedding request failed: {e}")
            raise ConnectionError(
                f"LM Studio embedding request failed: {e}\n"
                f"Make sure LM Studio is running at {self.base_url} with model '{self.model}' loaded."
            ) from e


class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """Embedding function that calls Ollama locally."""

    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None) -> None:
        self.model = model
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self._session = None

    def _get_session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []

        session = self._get_session()

        # Try batch API first
        try:
            resp = session.post(
                f"{self.base_url}/api/embed",
                json={"model": self.model, "input": input},
                timeout=60,
            )
            if resp.status_code != 404:
                resp.raise_for_status()
                data = resp.json()
                if "embeddings" in data:
                    return data["embeddings"]
                if "embedding" in data:
                    return [data["embedding"]]
        except Exception:
            pass

        # Fallback to single-item API
        out: List[List[float]] = []
        for t in input:
            r = session.post(
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


class HFSentenceTransformerEmbedding(embedding_functions.EmbeddingFunction):
    """Embedding function using sentence-transformers."""

    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer
        import torch

        self.model_name = model_name
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        logger.info(f"Loading sentence-transformers model: {model_name} on {device}")
        self.model = SentenceTransformer(model_name, device=device)

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []

        embeddings = self.model.encode(
            input,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        return embeddings.tolist()


class BGEM3EmbeddingFunction(embedding_functions.EmbeddingFunction):
    """
    Embedding function using BGE-M3 model.

    BGE-M3 is a state-of-the-art multilingual embedding model that supports:
    - Dense embeddings (1024 dimensions)
    - Sparse embeddings (for lexical matching)
    - ColBERT embeddings (for fine-grained matching)

    We use dense embeddings for ChromaDB compatibility.

    This class uses a singleton pattern to avoid loading the model multiple times.
    """

    _instance = None
    _model = None

    def __new__(cls, model_path: str = None):
        """Singleton pattern to avoid loading model multiple times."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, model_path: str = None) -> None:
        if BGEM3EmbeddingFunction._model is not None:
            return

        import torch

        self.model_path = model_path or BGE_M3_MODEL_PATH

        # Determine device
        if torch.cuda.is_available():
            self.device = "cuda"
        elif torch.backends.mps.is_available():
            self.device = "mps"
        else:
            self.device = "cpu"

        logger.info(f"Loading BGE-M3 model from: {self.model_path} on {self.device}")

        try:
            from FlagEmbedding import BGEM3FlagModel

            BGEM3EmbeddingFunction._model = BGEM3FlagModel(
                self.model_path,
                use_fp16=(self.device != "cpu"),
                device=self.device,
            )
            logger.info("BGE-M3 model loaded successfully")
        except ImportError:
            logger.warning("FlagEmbedding not installed. Falling back to sentence-transformers.")
            from sentence_transformers import SentenceTransformer
            BGEM3EmbeddingFunction._model = SentenceTransformer(
                self.model_path,
                device=self.device,
            )
            logger.info("BGE-M3 loaded via sentence-transformers")
        except Exception as e:
            logger.error(f"Failed to load BGE-M3: {e}")
            raise

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []

        model = BGEM3EmbeddingFunction._model

        try:
            # Check if it's a FlagEmbedding model
            if hasattr(model, 'encode'):
                result = model.encode(
                    input,
                    batch_size=32,
                    max_length=512,
                    return_dense=True,
                    return_sparse=False,
                    return_colbert_vecs=False,
                )
                # Result is a dict with 'dense_vecs' key
                if isinstance(result, dict):
                    embeddings = result.get('dense_vecs', result)
                else:
                    embeddings = result

                if hasattr(embeddings, 'tolist'):
                    return embeddings.tolist()
                return embeddings
            else:
                # sentence-transformers fallback
                embeddings = model.encode(
                    input,
                    show_progress_bar=False,
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                )
                return embeddings.tolist()
        except Exception as e:
            logger.error(f"BGE-M3 embedding failed: {e}")
            raise


def get_embedding_function() -> embedding_functions.EmbeddingFunction:
    """
    Get embedding function based on environment configuration.

    Reads MITRE_EMBED_BACKEND environment variable:
    - "bge-m3": BGE-M3 model (default, best quality)
    - "lmstudio": LM Studio API
    - "hf": HuggingFace sentence-transformers
    - "ollama": Ollama local model

    Returns:
        Configured EmbeddingFunction instance
    """
    backend = EMBED_BACKEND

    if backend == "bge-m3":
        logger.info(f"Using BGE-M3 embedding backend: {BGE_M3_MODEL_PATH}")
        return BGEM3EmbeddingFunction(model_path=BGE_M3_MODEL_PATH)

    if backend == "lmstudio":
        logger.info(f"Using LM Studio embedding backend: url={LMSTUDIO_BASE_URL} model={LMSTUDIO_EMBED_MODEL}")
        return LMStudioEmbeddingFunction(base_url=LMSTUDIO_BASE_URL, model=LMSTUDIO_EMBED_MODEL)

    if backend == "hf":
        logger.info(f"Using HuggingFace sentence-transformers backend: {HF_EMBED_MODEL}")
        return HFSentenceTransformerEmbedding(HF_EMBED_MODEL)

    if backend == "ollama":
        logger.info(f"Using Ollama backend: model={OLLAMA_EMBED_MODEL} base_url={OLLAMA_BASE_URL}")
        return OllamaEmbeddingFunction(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_BASE_URL)

    raise ValueError(f"Unknown EMBED_BACKEND={backend!r}. Expected 'bge-m3', 'lmstudio', 'hf', or 'ollama'.")


@lru_cache(maxsize=1)
def get_cached_embedding_function() -> embedding_functions.EmbeddingFunction:
    """Get cached embedding function (singleton)."""
    return get_embedding_function()
