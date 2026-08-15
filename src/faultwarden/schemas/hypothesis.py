"""Domain schemas for root-cause hypotheses and investigation findings."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HypothesisStatus(StrEnum):
    """Lifecycle status of a root-cause hypothesis as it is tested."""

    PROPOSED = "PROPOSED"
    TESTING = "TESTING"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Hypothesis(BaseModel):
    """A generated root-cause hypothesis explaining the incident."""

    id: str = Field(description="Unique hypothesis identifier")
    title: str = Field(description="Short summary of the hypothesis")
    description: str = Field(description="Detailed explanation of the potential failure mechanism")
    affected_component: str = Field(description="Service, database, or infrastructure component")
    confidence_score: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Confidence (0.0 - 1.0)"
    )
    status: HypothesisStatus = Field(default=HypothesisStatus.PROPOSED)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    refuting_evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HypothesisVerificationResult(BaseModel):
    """Result of testing/verifying a hypothesis against telemetry."""

    hypothesis_id: str
    verified: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    metrics_checked: list[str] = Field(default_factory=list)
    logs_checked: list[str] = Field(default_factory=list)


class RootCauseAnalysis(BaseModel):
    """Final root-cause determination for an incident."""

    primary_hypothesis_id: str
    summary: str
    root_cause_category: str = Field(
        description="e.g. CodeBug, ResourceExhaustion, ConfigError, DependencyFailure, HardwareFailure"
    )
    culprit_service: str
    contributing_factors: list[str] = Field(default_factory=list)
    technical_details: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
