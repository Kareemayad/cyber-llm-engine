# src/mitre_expert/models/enums.py
from typing import Literal

SectionType = Literal[
    # MITRE
    "description",
    "procedure_example",
    "mitigation",
    "detection_strategy",

    # D3FEND (choose the exact strings your d3fend_chunks_v1.jsonl uses)
    "d3fend_definition",
    "d3fend_kb_article",
    "d3fend_relations",
    "d3fend_references",
]
