"""
Knowledge constants for MITRE ATT&CK and D3FEND.

This module contains static mappings, synonyms, and taxonomy definitions
used for query expansion and intent classification.
"""

from mitre_expert.rag.knowledge.synonyms import MITRE_SYNONYMS, TACTIC_EXPANSIONS
from mitre_expert.rag.knowledge.tactics import (
    Tactic,
    TACTIC_KEY_TECHNIQUES,
    TACTIC_ID_TO_NAME,
    TACTIC_NAME_TO_ID,
    detect_tactic_from_query,
    get_key_techniques_for_tactic,
)

__all__ = [
    "MITRE_SYNONYMS",
    "TACTIC_EXPANSIONS",
    "Tactic",
    "TACTIC_KEY_TECHNIQUES",
    "TACTIC_ID_TO_NAME",
    "TACTIC_NAME_TO_ID",
    "detect_tactic_from_query",
    "get_key_techniques_for_tactic",
]
