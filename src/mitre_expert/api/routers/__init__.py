# src/mitre_expert/api/routers/__init__.py
from __future__ import annotations

from . import mitre_docqa
from . import mitre_mapper
from . import mitre_detect
from . import d3fend_docqa
from . import router  # existing "query_router" module
from . import chat  # NEW: Chat router with conversation memory

__all__ = [
    "mitre_docqa",
    "mitre_mapper",
    "mitre_detect",
    "d3fend_docqa",
    "router",
    "chat",
]