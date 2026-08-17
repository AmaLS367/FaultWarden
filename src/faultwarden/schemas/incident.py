"""Incident domain and API schemas."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from faultwarden.schemas.change import ChangeCorrelation, OperationalChange
from faultwarden.schemas.classification import IncidentClassification
from faultwarden.schemas.evidence import EvidenceItem
from faultwarden.schemas.hypothesis import Hypothesis, RootCauseAnalysis
from faultwarden.schemas.remediation import (
    RemediationEligibilityResult,
    RemediationProposal,
)


# --- Enums ---
class IncidentStatus(StrEnum):
    """Incident lifecycle state progression."""

    DETECTED = "DETECTED"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATING = "REMEDIATING"
    VALIDATING = "VALIDATING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"


class IncidentSeverity(StrEnum):
    """Incident severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# --- Domain Schemas ---
class IncidentBase(BaseModel):
    """Base fields shared across incident representations."""

    title: str = Field(description="Descriptive title of the incident")
    status: IncidentStatus = Field(default=IncidentStatus.DETECTED)
    severity: IncidentSeverity = Field(default=IncidentSeverity.MEDIUM)
    source: str = Field(
        default="alertmanager", description="Origin of incident (e.g. alertmanager, manual)"
    )
    summary: str | None = Field(
        default=None, description="Current executive summary of the incident"
    )
    fingerprint: str | None = Field(
        default=None, description="Stable alert fingerprint for deduplication and correlation"
    )
    service: str | None = Field(
        default=None, description="Name of the affected service or component"
    )
    alert_status: str | None = Field(
        default="firing", description="Current status of the upstream alert (e.g. firing, resolved)"
    )


class IncidentCreate(IncidentBase):
    """Schema for creating a new incident."""

    alert_payload: dict[str, Any] = Field(default_factory=dict, description="Raw alert payload")
    evidence: list[EvidenceItem] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    root_cause: RootCauseAnalysis | None = None
    proposed_remediations: list[RemediationProposal] = Field(default_factory=list)
    recent_changes: list[OperationalChange] = Field(default_factory=list)
    causal_changes: list[OperationalChange] = Field(default_factory=list)
    resolution: str | None = None
    classification: IncidentClassification | None = None
    iteration_count: int = 1


class IncidentUpdate(BaseModel):
    """Schema for updating incident fields during investigation."""

    title: str | None = None
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    summary: str | None = None
    fingerprint: str | None = None
    service: str | None = None
    alert_status: str | None = None
    langgraph_thread_id: str | None = None
    alert_payload: dict[str, Any] | None = None
    evidence: list[EvidenceItem] | None = None
    hypotheses: list[Hypothesis] | None = None
    root_cause: RootCauseAnalysis | None = None
    proposed_remediations: list[RemediationProposal] | None = None
    recent_changes: list[OperationalChange] | list[dict[str, Any]] | None = None
    causal_changes: list[OperationalChange] | list[dict[str, Any]] | None = None
    resolution: str | None = None
    classification: IncidentClassification | None = None
    iteration_count: int | None = None


class IncidentRead(IncidentBase):
    """Schema for reading incident details over API."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_payload: dict[str, Any] = Field(default_factory=dict)
    summary: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    root_cause: RootCauseAnalysis | None = None
    proposed_remediations: list[RemediationProposal] = Field(default_factory=list)
    recent_changes: list[OperationalChange] = Field(default_factory=list)
    causal_changes: list[OperationalChange] = Field(default_factory=list)
    resolution: str | None = None
    classification: IncidentClassification | None = None
    iteration_count: int = 1
    created_at: datetime
    updated_at: datetime


class InvestigationDetail(BaseModel):
    """Detailed investigation summary returned by dedicated investigation endpoints."""

    model_config = ConfigDict(from_attributes=True)

    incident_id: UUID
    status: IncidentStatus
    severity: IncidentSeverity
    service: str | None = None
    classification: IncidentClassification | None = None
    iteration_count: int = 1
    evidence: list[EvidenceItem] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    selected_hypothesis: Hypothesis | None = None
    root_cause: RootCauseAnalysis | None = None
    remediation_proposals: list[RemediationProposal] = Field(default_factory=list)
    remediation_eligibility: RemediationEligibilityResult | None = None
    recent_changes: list[OperationalChange] = Field(default_factory=list)
    change_correlations: list[ChangeCorrelation] = Field(default_factory=list)
    candidate_causal_changes: list[OperationalChange] = Field(default_factory=list)
    selected_causal_change: OperationalChange | None = None
    summary: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class IncidentFilter(BaseModel):
    """Query parameters for filtering incidents list."""

    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    source: str | None = None
    fingerprint: str | None = None
    service: str | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
