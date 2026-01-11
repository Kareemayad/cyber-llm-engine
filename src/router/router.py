# src/router/router.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Literal, Optional


RouteKind = Literal[
    "docqa",
    "mapper",
    "detect",
    "mapper_detect",
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
    Simple rule-based router for v1.

    Decides which MITRE specialist(s) to call:
      - docqa
      - mapper
      - detect
      - mapper_detect

    Notes:
    - dataset/mode are optional hints (so you can pass them from the API router).
      Today this router is MITRE-focused; for non-MITRE datasets the API router
      should override and use retrieval-only behavior (as we implemented).
    """
    q_raw = query or ""
    q = q_raw.lower()
    reasons: List[str] = []

    # Optional hints, useful for debugging / logging
    if dataset:
        reasons.append(f"dataset_hint={dataset}")
    if mode:
        reasons.append(f"mode_hint={mode}")

    # --- Technique-id detection (REAL) ---
    has_tech_id = bool(TECHID_RE.search(q_raw))
    if has_tech_id:
        reasons.append("mentions_tech_id")

    # --- Strong signals for mapping/log-style queries ---
    # Keep these relatively specific to avoid false positives.
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

    # --- Strong signals for detection/rules-style queries ---
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

    # Routing logic:

    # If it's clearly a detection question AND explicitly mentions a technique,
    # prefer MITRE-Detect directly.
    if has_detect and has_tech_id:
        return RouteDecision(kind="detect", reasons=reasons)

    # If clearly both mapping & detection but no explicit technique id:
    # use Mapper + Detect chain.
    if has_mapping and has_detect and not has_tech_id:
        return RouteDecision(kind="mapper_detect", reasons=reasons)

    # If looks like log/scenario → mapper
    if has_mapping and not has_detect:
        return RouteDecision(kind="mapper", reasons=reasons)

    # If asks about detection but not obviously a log → detect
    if has_detect and not has_mapping:
        return RouteDecision(kind="detect", reasons=reasons)

    # Default: DocQA
    return RouteDecision(kind="docqa", reasons=reasons)
