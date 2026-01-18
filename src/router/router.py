# src/router/router.py
"""
Query router with dataset-aware routing.

FIX Issue 5: Now properly routes based on dataset parameter
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Literal, Optional


RouteKind = Literal[
    "docqa",
    "mapper",
    "detect",
    "mapper_detect",
    "d3fend_docqa",  # NEW: explicit D3FEND route
]


@dataclass
class RouteDecision:
    kind: RouteKind
    reasons: List[str]


# Proper MITRE technique ID pattern: T#### or T####.###
TECHID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def route_query(
    query: str,
    dataset: Optional[str] = None,
    mode: Optional[str] = None,
) -> RouteDecision:
    """
    Rule-based router with dataset-aware logic.

    FIX Issue 5: Now dataset parameter actually affects routing

    Priority:
    1) Explicit dataset override
    2) Keyword-based detection
    3) Default to docqa
    """
    q_raw = query or ""
    q = q_raw.lower()
    reasons: List[str] = []

    # ------------------------------------------------------------
    # FIX Issue 5: Priority 1 - Explicit dataset routing
    # ------------------------------------------------------------
    if dataset:
        ds = dataset.strip().lower()

        if ds == "d3fend":
            reasons.append(f"explicit dataset={dataset}")
            return RouteDecision(kind="d3fend_docqa", reasons=reasons)

        if ds == "mitre":
            reasons.append(f"explicit dataset={dataset}")
            # Continue with MITRE routing logic below

        # For unknown datasets, log but continue
        if ds not in ("mitre", "d3fend"):
            reasons.append(f"unknown dataset={dataset}, treating as MITRE")

    # Optional mode hint (useful for debugging / logs)
    if mode:
        reasons.append(f"mode_hint={mode}")

    # ------------------------------------------------------------
    # Technique-id detection
    # ------------------------------------------------------------
    has_tech_id = bool(TECHID_RE.search(q_raw))
    if has_tech_id:
        reasons.append("mentions_tech_id")

    # ------------------------------------------------------------
    # Mapping keywords (log/scenario style)
    # ------------------------------------------------------------
    mapping_keywords = [
        "log ",
        "logs ",
        "alert",
        "siem",
        "event id",
        "eventid",
        "ioc",
        "indicator",
        "hash",
        "sha256",
        "md5",
        "ip ",
        "source ip",
        "destination ip",
        "dst ip",
        "src ip",
        "url ",
        "uri ",
        "user-agent",
        "dns ",
        "http",
        "https",
        "proxy",
        "firewall",
    ]
    has_mapping = any(kw in q for kw in mapping_keywords)
    if has_mapping:
        reasons.append("mapping_keywords")

    # ------------------------------------------------------------
    # Detection keywords (rules/detection style)
    # ------------------------------------------------------------
    detect_keywords = [
        "how to detect",
        "how would you detect",
        "detect this",
        "detect ",
        "detection",
        "sigma",
        "rule ",
        "rules ",
        "log source",
        "telemetry",
        "analytic",
        "detection idea",
        "use case",
        "hunting",
        "hunt ",
    ]
    has_detect = any(kw in q for kw in detect_keywords)
    if has_detect:
        reasons.append("detect_keywords")

    # ------------------------------------------------------------
    # D3FEND keywords (only if no explicit dataset was passed)
    # ------------------------------------------------------------
    if not dataset:
        d3fend_keywords = [
            "d3fend",
            "defense",
            "countermeasure",
            "mitigation",
            "defensive technique",
        ]
        has_d3fend = any(kw in q for kw in d3fend_keywords)
        if has_d3fend:
            reasons.append("d3fend_keywords")
            return RouteDecision(kind="d3fend_docqa", reasons=reasons)

    # ------------------------------------------------------------
    # MITRE routing logic
    # ------------------------------------------------------------

    # Detection + technique ID -> detect
    if has_detect and has_tech_id:
        return RouteDecision(kind="detect", reasons=reasons)

    # Mapping + detection (no technique) -> mapper_detect chain
    if has_mapping and has_detect and not has_tech_id:
        return RouteDecision(kind="mapper_detect", reasons=reasons)

    # Log/scenario -> mapper
    if has_mapping and not has_detect:
        return RouteDecision(kind="mapper", reasons=reasons)

    # Detection only -> detect
    if has_detect and not has_mapping:
        return RouteDecision(kind="detect", reasons=reasons)

    # Default: DocQA
    return RouteDecision(kind="docqa", reasons=reasons)
