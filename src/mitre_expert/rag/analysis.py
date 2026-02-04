"""
Query analysis and intent classification for RAG pipeline.

This module provides pure functions for analyzing user queries:
- Intent classification (detection, mitigation, procedure, etc.)
- Technique ID extraction
- Tactic detection
- Query expansion

All functions are side-effect free and don't make DB or model calls.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from mitre_expert.rag.knowledge import (
    MITRE_SYNONYMS,
    TACTIC_EXPANSIONS,
    Tactic,
    detect_tactic_from_query,
)


# Feature flag for query expansion
QUERY_EXPANSION_ENABLED = os.getenv("MITRE_QUERY_EXPANSION", "true").lower() == "true"


class QueryIntent(Enum):
    """Classification of user query intent."""

    TECHNIQUE_SPECIFIC = "technique_specific"  # Query mentions specific technique ID
    TACTIC_BROAD = "tactic_broad"  # Query about a tactic (lateral movement, etc.)
    DETECTION = "detection"  # How to detect something
    MITIGATION = "mitigation"  # How to prevent/mitigate
    PROCEDURE = "procedure"  # Examples, real-world usage
    DEFINITION = "definition"  # What is X?
    COMPARISON = "comparison"  # Compare A vs B
    DEFENSE = "defense"  # D3FEND countermeasures
    UNKNOWN = "unknown"


@dataclass
class QueryAnalysis:
    """Result of analyzing a user query."""

    original_query: str
    intent: QueryIntent
    detected_tactic: Optional[str] = None
    detected_tactic_id: Optional[str] = None
    detected_techniques: List[str] = field(default_factory=list)
    detected_sections: List[str] = field(default_factory=list)
    expanded_query: str = ""
    confidence: float = 0.0
    suggested_filters: Dict[str, Any] = field(default_factory=dict)


def detect_technique_ids_from_query(query: str) -> List[str]:
    """
    Extract MITRE ATT&CK technique IDs from query text.

    Supports:
    - T#### format (e.g., T1059)
    - T####.### format (e.g., T1059.001)

    Returns list of technique IDs in uppercase.
    """
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    matches = re.findall(pattern, query, re.IGNORECASE)
    return [m.upper() for m in matches]


# Alias for backward compatibility
detect_technique_ids = detect_technique_ids_from_query


def classify_intent(query: str) -> QueryIntent:
    """
    Classify the intent of a user query.

    This is a rule-based classifier using keyword matching.
    Order matters - more specific intents are checked first.
    """
    query_lower = query.lower()

    # Check for specific technique ID first (most specific)
    if re.search(r'\bT\d{4}', query, re.IGNORECASE):
        return QueryIntent.TECHNIQUE_SPECIFIC

    # Check for tactic references
    if detect_tactic_from_query(query):
        return QueryIntent.TACTIC_BROAD

    # Intent keywords (order matters for priority)
    detection_keywords = [
        "detect", "detection", "hunt", "find", "identify",
        "monitor", "alert", "log", "telemetry", "event"
    ]
    mitigation_keywords = [
        "mitigate", "mitigation", "prevent", "block", "defend",
        "protect", "stop", "remediate", "fix"
    ]
    defense_keywords = [
        "defense", "d3fend", "countermeasure", "counter", "defensive"
    ]
    procedure_keywords = [
        "example", "procedure", "how do", "how does", "real-world",
        "attack", "in the wild", "threat actor", "apt"
    ]
    definition_keywords = [
        "what is", "what are", "define", "explain", "describe",
        "overview", "summary"
    ]
    comparison_keywords = [
        "compare", "difference", "versus", "vs", "between"
    ]

    # Check each intent type
    if any(kw in query_lower for kw in detection_keywords):
        return QueryIntent.DETECTION
    if any(kw in query_lower for kw in mitigation_keywords):
        return QueryIntent.MITIGATION
    if any(kw in query_lower for kw in defense_keywords):
        return QueryIntent.DEFENSE
    if any(kw in query_lower for kw in procedure_keywords):
        return QueryIntent.PROCEDURE
    if any(kw in query_lower for kw in definition_keywords):
        return QueryIntent.DEFINITION
    if any(kw in query_lower for kw in comparison_keywords):
        return QueryIntent.COMPARISON

    return QueryIntent.UNKNOWN


# Alias for backward compatibility
classify_query_intent = classify_intent


def infer_sections_from_intent(intent: QueryIntent) -> List[str]:
    """Infer relevant chunk sections based on query intent."""
    section_map = {
        QueryIntent.DETECTION: ["detection_strategy"],
        QueryIntent.MITIGATION: ["mitigation"],
        QueryIntent.PROCEDURE: ["procedure_example"],
        QueryIntent.DEFINITION: ["description", "definition"],
        QueryIntent.DEFENSE: ["attack_mapping", "definition"],
    }
    return section_map.get(intent, [])


def expand_query_advanced(
    query: str,
    intent: QueryIntent,
    tactic_info: Optional[Tuple[str, str]] = None,
) -> str:
    """
    Advanced query expansion with intent and tactic awareness.

    This is the legacy interface. New code should use expand_query() with
    a QueryAnalysis object instead.

    Args:
        query: Original query string
        intent: Classified query intent
        tactic_info: Optional tuple of (tactic_name, tactic_id)

    Returns:
        Expanded query string
    """
    if not QUERY_EXPANSION_ENABLED:
        return query

    query_lower = query.lower()
    expansions: List[str] = []

    # Tactic-based expansion
    if tactic_info:
        tactic_name = tactic_info[0]
        if tactic_name in TACTIC_EXPANSIONS:
            expansions.extend(TACTIC_EXPANSIONS[tactic_name][:5])

    # Synonym-based expansion
    for term, synonyms in MITRE_SYNONYMS.items():
        if term in query_lower:
            expansions.extend(synonyms[:3])

    # Intent-based expansion
    if intent == QueryIntent.DETECTION:
        expansions.extend(["detection_strategy", "analytic", "log source", "data component"])
    elif intent == QueryIntent.MITIGATION:
        expansions.extend(["mitigation", "remediation", "countermeasure", "defense"])
    elif intent == QueryIntent.PROCEDURE:
        expansions.extend(["procedure", "example", "threat actor", "malware", "campaign"])

    if expansions:
        unique_expansions = list(dict.fromkeys(expansions))[:8]
        return f"{query} {' '.join(unique_expansions)}"

    return query


def expand_query(query: str, analysis: Optional[QueryAnalysis] = None) -> str:
    """
    Expand query with MITRE-specific synonyms and related terms.

    If analysis is provided, uses intent and tactic information for
    more targeted expansion. Otherwise, does basic synonym expansion.

    Args:
        query: Original query string
        analysis: Optional QueryAnalysis for intent-aware expansion

    Returns:
        Expanded query string
    """
    if not QUERY_EXPANSION_ENABLED:
        return query

    query_lower = query.lower()
    expansions: List[str] = []

    # Tactic-based expansion (if analysis provided)
    if analysis and analysis.detected_tactic:
        tactic_name = analysis.detected_tactic
        if tactic_name in TACTIC_EXPANSIONS:
            expansions.extend(TACTIC_EXPANSIONS[tactic_name][:5])

    # Synonym-based expansion
    for term, synonyms in MITRE_SYNONYMS.items():
        if term in query_lower:
            # Add fewer synonyms if analysis already added tactic expansions
            limit = 2 if expansions else 3
            expansions.extend(synonyms[:limit])

    # Intent-based expansion (if analysis provided)
    if analysis:
        if analysis.intent == QueryIntent.DETECTION:
            expansions.extend([
                "detection_strategy", "analytic", "log source", "data component"
            ])
        elif analysis.intent == QueryIntent.MITIGATION:
            expansions.extend([
                "mitigation", "remediation", "countermeasure", "defense"
            ])
        elif analysis.intent == QueryIntent.PROCEDURE:
            expansions.extend([
                "procedure", "example", "threat actor", "malware", "campaign"
            ])

    if expansions:
        # Deduplicate while preserving order
        unique_expansions = list(dict.fromkeys(expansions))[:8]
        return f"{query} {' '.join(unique_expansions)}"

    return query


def analyze_query(query: str) -> QueryAnalysis:
    """
    Perform comprehensive analysis of a user query.

    This function:
    1. Classifies intent (detection, mitigation, etc.)
    2. Detects tactic references (lateral movement, etc.)
    3. Extracts technique IDs (T1059, T1059.001, etc.)
    4. Infers relevant sections
    5. Expands the query with related terms
    6. Suggests metadata filters

    All operations are pure/deterministic - no DB or model calls.

    Args:
        query: User's query string

    Returns:
        QueryAnalysis with all extracted information
    """
    # Classify intent
    intent = classify_intent(query)

    # Detect tactic
    tactic_info = detect_tactic_from_query(query)

    # Extract technique IDs
    technique_ids = detect_technique_ids(query)

    # Infer sections based on intent
    sections = infer_sections_from_intent(intent)

    # Build suggested filters
    filters: Dict[str, Any] = {}
    if technique_ids:
        if len(technique_ids) == 1:
            filters["technique_id"] = technique_ids[0]
        else:
            filters["technique_id"] = {"$in": technique_ids}

    if sections and intent in [QueryIntent.DETECTION, QueryIntent.MITIGATION]:
        if len(sections) == 1:
            filters["section"] = sections[0]

    # Calculate confidence score
    confidence = 0.5  # Base confidence
    if technique_ids:
        confidence += 0.3
    if tactic_info:
        confidence += 0.2
    if intent != QueryIntent.UNKNOWN:
        confidence += 0.1

    # Create partial analysis for expansion
    partial_analysis = QueryAnalysis(
        original_query=query,
        intent=intent,
        detected_tactic=tactic_info[0] if tactic_info else None,
        detected_tactic_id=tactic_info[1] if tactic_info else None,
        detected_techniques=technique_ids,
        detected_sections=sections,
        confidence=min(confidence, 1.0),
    )

    # Expand query with analysis context
    expanded = expand_query(query, partial_analysis)

    return QueryAnalysis(
        original_query=query,
        intent=intent,
        detected_tactic=tactic_info[0] if tactic_info else None,
        detected_tactic_id=tactic_info[1] if tactic_info else None,
        detected_techniques=technique_ids,
        detected_sections=sections,
        expanded_query=expanded,
        confidence=min(confidence, 1.0),
        suggested_filters=filters,
    )
