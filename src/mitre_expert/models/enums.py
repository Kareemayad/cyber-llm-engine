# src/mitre_expert/models/enums.py

from typing import Literal

# Sections of text we will index for RAG
SectionType = Literal[
    "description",
    "procedure_example",
    "mitigation",
    "detection_strategy",
]
