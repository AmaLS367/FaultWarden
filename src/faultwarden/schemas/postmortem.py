"""Domain schemas for structured incident postmortems."""

from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Timeline Entry ---
class PostmortemTimelineEntry(BaseModel):
    """Single factual event in the incident resolution timeline."""

    timestamp: datetime = Field(description="Exact timestamp when the event occurred")
    event_type: str = Field(
        description="Event classification (e.g. ALERT_FIRED, INCIDENT_CREATED, ROOT_CAUSE_VERIFIED, REMEDIATION_EXECUTED, VALIDATION_PASSED, INCIDENT_RESOLVED)"
    )
    summary: str = Field(description="Concise description of the event")


# --- Incident Postmortem Domain Model ---
class IncidentPostmortem(BaseModel):
    """Complete structured postmortem document for a resolved incident."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(description="Unique postmortem identifier")
    incident_id: UUID = Field(description="Associated incident identifier")
    title: str = Field(description="Postmortem title")
    impact_summary: str = Field(
        description="Executive summary of customer/service impact and outage extent"
    )
    detection_summary: str = Field(
        description="How the incident was detected (alert rule, metrics, source)"
    )
    timeline: list[PostmortemTimelineEntry] = Field(
        default_factory=list,
        description="Chronological sequence of verified events using real persisted timestamps",
    )
    root_cause_summary: str = Field(description="Verified root cause analysis")
    root_cause_category: str = Field(description="Category classification of the root cause")
    contributing_factors: list[str] = Field(
        default_factory=list, description="Underlying factors contributing to the incident"
    )
    evidence_summary: str = Field(description="Summary of telemetry evidence confirming root cause")
    remediation_summary: str = Field(
        description="Factual summary of executed remediation action(s)"
    )
    validation_summary: str = Field(
        description="Factual results of multi-signal recovery validation"
    )
    resolution_summary: str = Field(description="Final resolution confirmation")
    lessons_learned: list[str] = Field(
        default_factory=list, description="Actionable takeaways and organizational learnings"
    )
    follow_up_actions: list[str] = Field(
        default_factory=list,
        description="Preventative follow-up tasks to avoid recurrence",
    )
    similar_historical_incidents: list[str] = Field(
        default_factory=list,
        description="UUIDs of historical incidents retrieved as context during investigation",
    )
    started_at: datetime = Field(description="Incident start/detection timestamp")
    resolved_at: datetime = Field(description="Incident resolution timestamp")
    duration_seconds: float = Field(description="Total incident duration in seconds")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --- LLM Structured Synthesis Models ---
class PostmortemSynthesisResponse(BaseModel):
    """Structured response container for LLM synthesis of postmortem prose."""

    impact_summary: str = Field(
        description="Concise synthesis of user and system impact based on telemetry"
    )
    lessons_learned: list[str] = Field(
        default_factory=list,
        description="1 to 3 concise SRE lessons learned from this incident",
    )
    follow_up_actions: list[str] = Field(
        default_factory=list,
        description="1 to 3 concrete preventative follow-up actions",
    )
