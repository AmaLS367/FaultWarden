"""Domain schemas for reusable incident memory and similarity search."""

from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Incident Memory Domain Models ---
class IncidentMemory(BaseModel):
    """Compact, reusable memory representation of a resolved and validated incident."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(description="Unique memory record identifier")
    incident_id: UUID = Field(description="Associated incident identifier")
    service: str = Field(description="Target service name")
    classification: str = Field(description="Incident classification category")
    severity: str = Field(description="Incident severity level")
    symptoms_summary: str = Field(description="Concise description of initial symptoms and alerts")
    root_cause_summary: str = Field(description="Verified root cause explanation")
    root_cause_category: str = Field(description="Root cause category code")
    evidence_summary: str = Field(description="Summary of key corroborating telemetry evidence")
    successful_remediation_summary: str = Field(
        description="Summary of the remediation action that resolved the incident"
    )
    successful_action_type: str | None = Field(
        default=None, description="ActionType enum string of the successful remediation"
    )
    failed_remediation_summaries: list[str] = Field(
        default_factory=list, description="Summaries of any remediation attempts that failed"
    )
    validation_summary: str = Field(description="Summary of multi-signal post-remediation recovery")
    resolution_summary: str = Field(description="Final incident resolution statement")
    postmortem_id: UUID | None = Field(
        default=None, description="Associated postmortem identifier if generated"
    )
    resolved_at: datetime = Field(description="Timestamp when the incident was resolved")
    incident_duration_seconds: float = Field(
        description="Total duration from incident creation to resolution in seconds"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SimilarIncidentMemory(BaseModel):
    """Search result representing a historically similar resolved incident."""

    model_config = ConfigDict(from_attributes=True)

    incident_id: UUID = Field(description="Historical incident identifier")
    memory_id: UUID = Field(description="Historical memory record identifier")
    similarity: float = Field(
        ge=0.0, le=1.0, description="Calculated cosine similarity score (0.0 to 1.0)"
    )
    service: str = Field(description="Service name of the historical incident")
    classification: str = Field(description="Historical incident classification")
    severity: str = Field(description="Historical incident severity")
    symptoms_summary: str = Field(description="Observed symptoms from the past incident")
    root_cause_summary: str = Field(description="Verified root cause of the past incident")
    root_cause_category: str = Field(description="Root cause category of the past incident")
    successful_remediation_summary: str = Field(
        description="Action that resolved the past incident"
    )
    successful_action_type: str | None = Field(
        default=None, description="ActionType of the historical remediation"
    )
    validation_summary: str = Field(description="Validation result confirming past recovery")
    resolved_at: datetime = Field(description="Resolution timestamp of the past incident")


# --- API Query & Response Models ---
class MemorySearchQuery(BaseModel):
    """Payload for similarity search requests."""

    query: str = Field(description="Natural language or symptom description to search for")
    service: str | None = Field(
        default=None, description="Optional service name filter for matching"
    )
    classification: str | None = Field(
        default=None, description="Optional classification category filter"
    )
    limit: int = Field(
        default=5, ge=1, le=20, description="Maximum number of similar memories to return"
    )
    min_similarity: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Minimum cosine similarity threshold to qualify as a match",
    )


class MemorySearchResponse(BaseModel):
    """Response containing bounded list of similar historical incidents."""

    results: list[SimilarIncidentMemory] = Field(default_factory=list)
    total_found: int = Field(description="Number of matching memory records above threshold")
