# src/mitre_expert/api/routers/mitre_mapper.py
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from mitre_expert.llm.mitre_mapper import (
    map_text_to_techniques,
    mapper_result_to_dict,
)

router = APIRouter(
    prefix="/mapper",
    tags=["mitre-mapper"],
)


class MapperRequest(BaseModel):
    text: str = Field(
        ...,
        description="Log line, SIEM alert description, or CTI snippet to map to MITRE techniques.",
    )
    max_techniques: int = Field(
        5,
        ge=1,
        le=10,
        description="Maximum number of techniques to return.",
    )
    observed_log_sources: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of observed / available log sources "
            "(e.g. ['WinEventLog:Security', 'azure:signinlogs']). "
            "Used as a weak prior to favor techniques whose telemetry overlaps."
        ),
    )
    observed_data_components: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of MITRE data component IDs observed in the environment "
            "(e.g. ['DC0002', 'DC0032']). Used as a weak prior."
        ),
    )


class TechniqueOut(BaseModel):
    id: str
    name: str | None = Field(
        None,
        description="MITRE technique name, if resolved from metadata.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Relative confidence (0–1) for this technique.",
    )
    tactics: List[str] = Field(
        default_factory=list,
        description="List of associated tactic IDs (e.g. ['TA0002', 'TA0008']).",
    )
    data_components: List[str] = Field(
        default_factory=list,
        description="Telemetry data component IDs associated with this technique.",
    )
    log_sources: List[str] = Field(
        default_factory=list,
        description="Log source names associated with this technique.",
    )


class MapperResponse(BaseModel):
    tactics: List[str] = Field(
        ...,
        description="Deduplicated list of tactic IDs derived from the mapped techniques.",
    )
    techniques: List[TechniqueOut]


@router.post("", response_model=MapperResponse)
async def mapper_endpoint(payload: MapperRequest) -> MapperResponse:
    """
    MITRE-Mapper endpoint.

    Uses deterministic technique resolver + semantic search + MITRE metadata
    (including telemetry enrichment) to produce a list of likely techniques and tactics.

    If observed_log_sources / observed_data_components are provided, they are used
    as a weak prior to nudge scores toward techniques whose telemetry overlaps.
    """
    result = map_text_to_techniques(
        text=payload.text,
        max_techniques=payload.max_techniques,
        observed_log_sources=payload.observed_log_sources,
        observed_data_components=payload.observed_data_components,
    )
    data = mapper_result_to_dict(result)
    return MapperResponse(**data)
