# src/mitre_expert/models/enums.py
"""
Type definitions for MITRE Expert models.

These are Literal types used for type checking and documentation.
They define the allowed values for categorical fields.
"""

from typing import Literal, Union

# ---------------------------------------------------------------------------
# MITRE ATT&CK Section Types
# ---------------------------------------------------------------------------

MitreSectionType = Literal[
    "description",
    "procedure_example",
    "mitigation",
    "detection_strategy",
]

# ---------------------------------------------------------------------------
# D3FEND Section Types
# ---------------------------------------------------------------------------

D3fendSectionType = Literal[
    "definition",
    "kb_article",
    "relations",
    "attack_mappings",   # Summary of all ATT&CK mappings
    "attack_mapping",    # Per-technique mapping chunk
    "minimal",           # Fallback chunk with minimal info
]

# ---------------------------------------------------------------------------
# Combined Section Type (for code that handles both)
# ---------------------------------------------------------------------------

SectionType = Union[MitreSectionType, D3fendSectionType]

# Alternative: Single Literal with all values
# This is simpler but less semantically clear
SectionType = Literal[
    # MITRE
    "description",
    "procedure_example",
    "mitigation",
    "detection_strategy",
    # D3FEND
    "definition",
    "kb_article",
    "relations",
    "attack_mappings",
    "attack_mapping",
    "minimal",
    # Fallback
    "unknown",
]

# ---------------------------------------------------------------------------
# Dataset Types
# ---------------------------------------------------------------------------

DatasetType = Literal[
    "mitre",
    "d3fend",
    "all",
]

# ---------------------------------------------------------------------------
# Retrieval Mode Types
# ---------------------------------------------------------------------------

RetrievalMode = Literal[
    "search",  # Semantic search
    "get",     # Deterministic filter-based lookup
]

# ---------------------------------------------------------------------------
# Route Types (from router.py)
# ---------------------------------------------------------------------------

RouteKind = Literal[
    "mapper",
    "detect",
    "mapper_detect",
    "docqa",
    "retrieval",  # For dataset=all retrieval-only mode
]

# ---------------------------------------------------------------------------
# Chunk Source Types
# ---------------------------------------------------------------------------

ChunkSource = Literal[
    "mitre_knowledge_pack_v1",
    "d3fend_chunks_v1",
]

# ---------------------------------------------------------------------------
# Platform Types (common MITRE platforms)
# ---------------------------------------------------------------------------

PlatformType = Literal[
    "Windows",
    "Linux",
    "macOS",
    "IaaS",
    "SaaS",
    "Office 365",
    "Azure AD",
    "Google Workspace",
    "Containers",
    "Network",
    "PRE",  # Pre-compromise
]