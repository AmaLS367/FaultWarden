"""Remediation proposal and safety tier schemas."""

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, Field


# --- Safety Enums ---
class RemediationSafetyLevel(IntEnum):
    """Three-tier safety classification for incident remediations."""

    LEVEL_0_READ_ONLY = 0
    LEVEL_1_SAFE_AUTOMATIC = 1
    LEVEL_2_HUMAN_APPROVAL_REQUIRED = 2


class RemediationStatus(StrEnum):
    """Lifecycle status for remediation proposals."""

    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


# --- Remediation Actions & Proposals ---
class RemediationAction(BaseModel):
    """Discrete executable remediation step."""

    id: str
    name: str
    target_service: str
    safety_level: RemediationSafetyLevel
    action_type: str = Field(
        description="e.g. restart_service, rollback_deployment, clear_cache, scale_replicas"
    )
    parameters: dict[str, Any] = Field(default_factory=dict)
    description: str


class RemediationProposal(BaseModel):
    """Complete remediation proposal containing one or more actions."""

    id: str
    incident_id: str
    title: str
    summary: str
    highest_safety_level: RemediationSafetyLevel
    requires_human_approval: bool
    status: RemediationStatus = RemediationStatus.PROPOSED
    actions: list[RemediationAction] = Field(default_factory=list)
    estimated_impact: str = ""
    rollback_plan: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
