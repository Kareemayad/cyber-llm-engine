"""
Reranking module for RAG pipeline.

This module provides cross-encoder reranking using:
- BGE-Reranker-v2-M3 (preferred, best quality)
- sentence-transformers CrossEncoder (fallback)

Reranking improves precision by scoring query-document pairs together,
rather than independently embedding them.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from mitre_expert.config import BGE_RERANKER_MODEL_PATH

logger = logging.getLogger("mitre_expert.rerank")


# Feature flags
RERANK_ENABLED = os.getenv("MITRE_RERANK_ENABLED", "true").lower() == "true"
STRICT_MODE = os.getenv("MITRE_STRICT_MODE", "false").lower() == "true"
MIN_RERANK_SCORE = float(os.getenv("MITRE_MIN_RERANK_SCORE", "0.3"))


# Module-level reranker cache
_RERANKER = None
_RERANKER_TYPE: Optional[str] = None  # "bge" or "cross-encoder"


@dataclass
class RerankResult:
    """Result of reranking operation with explicit score fields."""

    ids: List[str]
    docs: List[str]
    metas: List[Dict[str, Any]]
    rerank_scores: List[float]  # Higher = better, normalized 0-1
    original_indices: List[int]  # Original indices before reranking


def _get_reranker():
    """
    Get or create reranker, preferring BGE-Reranker-v2-M3.

    Tries loading in order:
    1. BGE FlagReranker (best quality)
    2. Local BGE via CrossEncoder
    3. MS-MARCO CrossEncoder fallback
    """
    global _RERANKER, _RERANKER_TYPE

    if not RERANK_ENABLED:
        return None

    if _RERANKER is not None:
        return _RERANKER

    # Try BGE Reranker first (best quality)
    try:
        from FlagEmbedding import FlagReranker
        import torch

        device = "cuda" if torch.cuda.is_available() else ("mps" if torch.backends.mps.is_available() else "cpu")
        logger.info(f"Loading BGE-Reranker-v2-M3 from: {BGE_RERANKER_MODEL_PATH} on {device}")

        _RERANKER = FlagReranker(
            BGE_RERANKER_MODEL_PATH,
            use_fp16=(device != "cpu"),
            device=device,
        )
        _RERANKER_TYPE = "bge"
        logger.info("BGE-Reranker-v2-M3 loaded successfully")
        return _RERANKER
    except ImportError:
        logger.info("FlagEmbedding not available, trying sentence-transformers CrossEncoder...")
    except Exception as e:
        logger.warning(f"Failed to load BGE reranker: {e}. Trying CrossEncoder fallback...")

    # Fallback to CrossEncoder
    try:
        from sentence_transformers import CrossEncoder
        import torch

        device = "cuda" if torch.cuda.is_available() else ("mps" if torch.backends.mps.is_available() else "cpu")

        # Try loading local BGE reranker as CrossEncoder
        try:
            logger.info(f"Trying to load BGE reranker via CrossEncoder: {BGE_RERANKER_MODEL_PATH}")
            _RERANKER = CrossEncoder(
                BGE_RERANKER_MODEL_PATH,
                max_length=512,
                device=device,
            )
            _RERANKER_TYPE = "cross-encoder"
            logger.info("BGE reranker loaded via CrossEncoder")
            return _RERANKER
        except Exception:
            pass

        # Final fallback to ms-marco
        logger.info("Loading fallback cross-encoder: cross-encoder/ms-marco-MiniLM-L-6-v2")
        _RERANKER = CrossEncoder(
            "cross-encoder/ms-marco-MiniLM-L-6-v2",
            max_length=512,
            device=device,
        )
        _RERANKER_TYPE = "cross-encoder"
        return _RERANKER
    except ImportError:
        logger.warning("sentence-transformers not installed. Reranking disabled.")
        return None
    except Exception as e:
        logger.warning(f"Failed to load reranker: {e}")
        return None


def is_reranking_available() -> bool:
    """Check if reranking is available and enabled."""
    if not RERANK_ENABLED:
        return False
    return _get_reranker() is not None


def get_reranker_type() -> Optional[str]:
    """Get the type of reranker loaded ("bge" or "cross-encoder")."""
    global _RERANKER_TYPE
    if _RERANKER is None:
        _get_reranker()  # Initialize if needed
    return _RERANKER_TYPE


def rerank(
    query: str,
    ids: List[str],
    docs: List[str],
    metas: List[Dict[str, Any]],
    top_k: int,
    min_score: float = MIN_RERANK_SCORE,
) -> RerankResult:
    """
    Rerank results using cross-encoder.

    Args:
        query: The query string
        ids: Document IDs
        docs: Document texts
        metas: Document metadata
        top_k: Number of results to return
        min_score: Minimum score threshold (only applied in strict mode)

    Returns:
        RerankResult with reranked results and explicit rerank_scores.
        rerank_scores are always higher = better, normalized to 0-1.
    """
    reranker = _get_reranker()

    if reranker is None or len(ids) == 0:
        return RerankResult(
            ids=ids[:top_k],
            docs=docs[:top_k],
            metas=metas[:top_k],
            rerank_scores=[],
            original_indices=list(range(min(top_k, len(ids)))),
        )

    if len(ids) <= top_k:
        return RerankResult(
            ids=ids,
            docs=docs,
            metas=metas,
            rerank_scores=[],
            original_indices=list(range(len(ids))),
        )

    try:
        if _RERANKER_TYPE == "bge":
            # BGE FlagReranker uses compute_score
            pairs = [[query, doc] for doc in docs]
            scores = reranker.compute_score(pairs, normalize=True)
            if not isinstance(scores, list):
                scores = [scores]
        else:
            # CrossEncoder uses predict
            pairs = [(query, doc) for doc in docs]
            scores = reranker.predict(pairs)
            if not hasattr(scores, '__iter__'):
                scores = [scores]
            scores = list(scores)
    except Exception as e:
        logger.warning(f"Reranking failed: {e}. Returning unranked results.")
        return RerankResult(
            ids=ids[:top_k],
            docs=docs[:top_k],
            metas=metas[:top_k],
            rerank_scores=[],
            original_indices=list(range(min(top_k, len(ids)))),
        )

    # Create tuples with original index for tracking
    indexed_results = list(enumerate(zip(ids, docs, metas, scores)))
    ranked = sorted(indexed_results, key=lambda x: x[1][3], reverse=True)

    # Apply strict mode filtering if enabled
    if STRICT_MODE:
        ranked = [r for r in ranked if r[1][3] >= min_score]

    ranked = ranked[:top_k]

    if not ranked:
        logger.warning(f"All results filtered out by min_score={min_score}. Returning top results anyway.")
        ranked = sorted(indexed_results, key=lambda x: x[1][3], reverse=True)[:top_k]

    return RerankResult(
        ids=[r[1][0] for r in ranked],
        docs=[r[1][1] for r in ranked],
        metas=[r[1][2] for r in ranked],
        rerank_scores=[float(r[1][3]) for r in ranked],
        original_indices=[r[0] for r in ranked],
    )


def rerank_with_distances(
    query: str,
    ids: List[str],
    docs: List[str],
    metas: List[Dict[str, Any]],
    semantic_distances: List[float],
    top_k: int,
    min_score: float = MIN_RERANK_SCORE,
) -> Tuple[RerankResult, List[float]]:
    """
    Rerank results and preserve aligned semantic distances.

    Args:
        query: The query string
        ids: Document IDs
        docs: Document texts
        metas: Document metadata
        semantic_distances: Original cosine distances from embedding search
        top_k: Number of results to return
        min_score: Minimum score threshold (only applied in strict mode)

    Returns:
        Tuple of (RerankResult, aligned_semantic_distances)
    """
    result = rerank(query, ids, docs, metas, top_k, min_score)

    # Reorder semantic_distances to match reranked order
    aligned_distances = [
        semantic_distances[i] if i < len(semantic_distances) else 1.0
        for i in result.original_indices
    ]

    return result, aligned_distances
