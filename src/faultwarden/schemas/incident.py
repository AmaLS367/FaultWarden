"""Incident domain and API schemas."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from faultwarden.schemas.evidence import EvidenceItem
from faultwarden.schemas.hypothesis import Hypothesis, RootCauseAnalysis
from faultwarden.schemas.remediation import RemediationProposal


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


class IncidentCreate(IncidentBase):
    """Schema for creating a new incident."""

    alert_payload: dict[str, Any] = Field(default_factory=dict, description="Raw alert payload")
    evidence: list[EvidenceItem] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    root_cause: RootCauseAnalysis | None = None
    proposed_remediations: list[RemediationProposal] = Field(default_factory=list)
    resolution: str | None = None


class IncidentUpdate(BaseModel):
    """Schema for updating incident fields during investigation."""

    title: str | None = None
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    summary: str | None = None
    evidence: list[EvidenceItem] | None = None
    hypotheses: list[Hypothesis] | None = None
    root_cause: RootCauseAnalysis | None = None
    proposed_remediations: list[RemediationProposal] | None = None
    resolution: str | None = None


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
    resolution: str | None = None
    created_at: datetime
    updated_at: datetime


class IncidentFilter(BaseModel):
    """Query parameters for filtering incidents list."""

    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    source: str | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
