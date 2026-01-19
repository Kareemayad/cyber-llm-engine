#src/mitre_expert/chat/coreference.py
"""
Coreference resolution for conversational MITRE assistant.

Handles cases like:
- "What is T1059?" -> "How do I detect it?" (it = T1059)
- "Tell me about PowerShell attacks" -> "What are its mitigations?" (its = the technique)
- "What about sub-techniques?" -> injects context about current technique

This is a lightweight rule-based approach. For production, consider
using a proper coreference resolution model.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .session import ChatSession


# Patterns that suggest the user is referring to something mentioned earlier
PRONOUN_PATTERNS = [
    # Direct pronouns
    (r"\b(it|this|that)\b(?!\s+technique)", "pronoun"),
    (r"\b(this technique|that technique|the technique)\b", "technique_ref"),
    (r"\b(this attack|that attack|the attack)\b", "attack_ref"),
    
    # Possessive references
    (r"\b(its|their)\s+(mitigations?|detections?|tactics?|procedures?|sub-?techniques?)\b", "possessive"),
    
    # Implicit references
    (r"\bhow (do i|to|would you|can i|should i) detect (it|this|that)\b", "detect_ref"),
    (r"\bhow (do i|to|would you|can i|should i) mitigate (it|this|that)\b", "mitigate_ref"),
    (r"\bhow (do i|to|would you|can i|should i) prevent (it|this|that)\b", "prevent_ref"),
    
    # Continuation phrases
    (r"\bwhat about\b", "continuation"),
    (r"\btell me more\b", "continuation"),
    (r"\bmore details?\b", "continuation"),
    (r"\bexplain (it|this|that|further|more)\b", "explain_ref"),
    (r"\bgo (deeper|further)\b", "continuation"),
    (r"\bwhat else\b", "continuation"),
    
    # Comparative/follow-up
    (r"\band (its|the) (sub-?techniques?|variants?|related)\b", "subtechnique_ref"),
    (r"\bwhat are (its|the) (sub-?techniques?)\b", "subtechnique_ref"),
]

# Compiled patterns for efficiency
_COMPILED_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE), name) for p, name in PRONOUN_PATTERNS
]

# Pattern to detect explicit technique IDs
TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _has_explicit_technique(query: str) -> bool:
    """Check if the query already contains an explicit technique ID."""
    return bool(TECHNIQUE_ID_PATTERN.search(query))


def _detect_coreference_type(query: str) -> Optional[str]:
    """
    Detect what type of coreference pattern is present.
    
    Returns the pattern type name, or None if no coreference detected.
    """
    q_lower = query.lower()
    for pattern, pattern_type in _COMPILED_PATTERNS:
        if pattern.search(q_lower):
            return pattern_type
    return None


def resolve_coreferences(query: str, session: ChatSession) -> str:
    """
    Resolve pronouns and references to explicit technique IDs.
    
    Takes a user query and the current session context, and returns
    a modified query with pronouns replaced by explicit references.
    
    Examples:
        Input:  "How do I detect it?"
        Output: "How do I detect T1059?"  (if T1059 is current context)
        
        Input:  "What are its mitigations?"
        Output: "What are T1059 mitigations?"
        
        Input:  "Tell me more"
        Output: "Tell me more about T1059"
    
    Args:
        query: The user's raw query
        session: Current chat session with context
    
    Returns:
        Resolved query with explicit technique references
    """
    # If no current technique context, can't resolve
    if not session.current_technique_id:
        return query
    
    # If query already has explicit technique ID, no resolution needed
    if _has_explicit_technique(query):
        return query
    
    # Detect coreference type
    coref_type = _detect_coreference_type(query)
    if not coref_type:
        return query
    
    tid = session.current_technique_id
    tname = session.current_technique_name or ""
    
    resolved = query
    
    # Apply resolution based on pattern type
    if coref_type == "pronoun":
        # Replace standalone pronouns: "it", "this", "that"
        resolved = re.sub(
            r"\b(it|this|that)\b(?!\s+technique|\s+attack)",
            tid,
            resolved,
            flags=re.IGNORECASE,
        )
    
    elif coref_type in ("technique_ref", "attack_ref"):
        # Replace "this technique", "that attack", etc.
        resolved = re.sub(
            r"\b(this|that|the)\s+(technique|attack)\b",
            tid,
            resolved,
            flags=re.IGNORECASE,
        )
    
    elif coref_type == "possessive":
        # Replace "its mitigations" -> "T1059 mitigations"
        resolved = re.sub(
            r"\b(its|their)\s+",
            f"{tid} ",
            resolved,
            flags=re.IGNORECASE,
        )
    
    elif coref_type in ("detect_ref", "mitigate_ref", "prevent_ref"):
        # Replace "detect it" -> "detect T1059"
        resolved = re.sub(
            r"\b(detect|mitigate|prevent)\s+(it|this|that)\b",
            rf"\1 {tid}",
            resolved,
            flags=re.IGNORECASE,
        )
    
    elif coref_type == "continuation":
        # Append context for continuation phrases
        # "What about" -> "What about T1059"
        # "Tell me more" -> "Tell me more about T1059"
        if "what about" in resolved.lower():
            resolved = re.sub(
                r"\bwhat about\b",
                f"what about {tid}",
                resolved,
                flags=re.IGNORECASE,
            )
        elif not tid.lower() in resolved.lower():
            # Append context if not already present
            resolved = f"{resolved.rstrip('?.')} regarding {tid}"
    
    elif coref_type == "explain_ref":
        resolved = re.sub(
            r"\bexplain\s+(it|this|that|further|more)\b",
            f"explain {tid}",
            resolved,
            flags=re.IGNORECASE,
        )
    
    elif coref_type == "subtechnique_ref":
        # "what are its sub-techniques" -> "what are T1059 sub-techniques"
        resolved = re.sub(
            r"\b(its|the)\s+(sub-?techniques?)\b",
            rf"{tid} \2",
            resolved,
            flags=re.IGNORECASE,
        )
    
    return resolved


def extract_technique_from_response(
    response_text: str,
    techniques_list: Optional[List[dict]] = None,
) -> Optional[str]:
    """
    Extract the primary technique ID from an assistant response.
    
    Used to update session context after a response.
    
    Args:
        response_text: The assistant's response text
        techniques_list: Optional list of technique dicts from structured response
    
    Returns:
        Primary technique ID if found, else None
    """
    # First, check structured techniques list
    if techniques_list:
        for t in techniques_list:
            if isinstance(t, dict):
                tid = t.get("id") or t.get("technique_id")
                if tid:
                    return tid.upper()
    
    # Fall back to regex extraction from text
    match = TECHNIQUE_ID_PATTERN.search(response_text)
    if match:
        return match.group(0).upper()
    
    return None


def build_context_injection(session: ChatSession) -> Optional[str]:
    """
    Build a context string to inject into the LLM prompt.
    
    This helps the LLM understand the conversation context
    without relying purely on coreference resolution.
    
    Returns None if no relevant context to inject.
    """
    if not session.current_technique_id:
        return None
    
    parts = []
    
    tid = session.current_technique_id
    tname = session.current_technique_name
    
    if tname:
        parts.append(f"[Context: Currently discussing {tid} ({tname})]")
    else:
        parts.append(f"[Context: Currently discussing {tid}]")
    
    if session.current_tactics:
        parts.append(f"[Tactics: {', '.join(session.current_tactics)}]")
    
    return " ".join(parts) if parts else None
