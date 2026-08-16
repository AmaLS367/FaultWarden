"""Incident classification schemas and category taxonomy."""

from enum import StrEnum

from pydantic import BaseModel, Field


# --- Enums ---
class IncidentCategory(StrEnum):
    """Categorization taxonomy for detected incidents."""

    HTTP_ERRORS = "HTTP_ERRORS"
    LATENCY = "LATENCY"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    UNKNOWN = "UNKNOWN"


# --- Classification Schema ---
class IncidentClassification(BaseModel):
    """Structured incident classification determination."""

    category: IncidentCategory = Field(
        default=IncidentCategory.UNKNOWN, description="Primary incident category"
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Classification confidence score (0.0 to 1.0)"
    )
    reasoning: str = Field(
        default="", description="Reasoning summary supporting this classification"
    )
    suggested_queries: list[str] = Field(
        default_factory=list, description="Suggested PromQL metric queries for this category"
    )
    suggested_log_filters: list[str] = Field(
        default_factory=list, description="Suggested Loki LogQL filters for this category"
    )
