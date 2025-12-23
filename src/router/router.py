# src/router/router.py
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal


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


def route_query(query: str) -> RouteDecision:
    """
    Very simple rule-based router for v1.

    Decides which MITRE specialist(s) to call:
      - docqa
      - mapper
      - detect
      - mapper_detect
    """
    q = (query or "").lower()
    reasons: List[str] = []

    # Strong signals for mapping/log-style queries
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
        "ip ",
        "source ip",
        "destination ip",
        "url ",
        "connection",
        "network flow",
    ]
    has_mapping = any(kw in q for kw in mapping_keywords)
    if has_mapping:
        reasons.append("mapping_keywords")

    # Strong signals for detection/rules-style queries
    detect_keywords = [
        "how to detect",
        "how would you detect",
        "detect this",
        "detect ",
        "sigma",
        "rule ",
        "rules ",
        "log source",
        "telemetry",
        "detection idea",
        "use case",
    ]
    has_detect = any(kw in q for kw in detect_keywords)
    if has_detect:
        reasons.append("detect_keywords")

    # Technique-id style query: very rough pattern (T#### / T####.###)
    has_tech_id = "t1" in q or "t10" in q or "t15" in q or "t11" in q
    if has_tech_id:
        reasons.append("mentions_tech_id_like_pattern")

    # If it's clearly a detection question AND explicitly mentions a technique,
    # prefer MITRE-Detect directly.
    if has_detect and has_tech_id:
        return RouteDecision(kind="detect", reasons=reasons)

    # If clearly both mapping & detection but no explicit technique id:
    # use Mapper + Detect chain.
    if has_mapping and has_detect:
        return RouteDecision(kind="mapper_detect", reasons=reasons)

    # If looks like log/scenario → mapper
    if has_mapping:
        return RouteDecision(kind="mapper", reasons=reasons)

    # If asks about detection but not obviously a log → detect
    if has_detect:
        return RouteDecision(kind="detect", reasons=reasons)

    # Default: DocQA
    return RouteDecision(kind="docqa", reasons=reasons)
