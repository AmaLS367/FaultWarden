"""Remediation proposal and safety tier schemas."""

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


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
    AWAITING_APPROVAL = "AWAITING_APPROVAL"


class ActionType(StrEnum):
    """Closed registry of executable remediation actions supported in v0.3."""

    RESET_DEMO_FAILURE = "RESET_DEMO_FAILURE"
    RESTART_REGISTERED_SERVICE = "RESTART_REGISTERED_SERVICE"


# --- Action Parameters ---
class ResetDemoFailureParameters(BaseModel):
    """Parameters for resetting demo service failure modes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: Literal["demo-service"] = "demo-service"


class RestartRegisteredServiceParameters(BaseModel):
    """Parameters for restarting a registered service in the demo environment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_id: Literal["demo-service"] = "demo-service"


# --- Pre-Policy Remediation Proposals (LLM-Facing) ---
class _RemediationProposalBase(BaseModel):
    """Base schema for pre-policy remediation proposals suggested by LLM reasoning.

    IMPORTANT SAFETY INVARIANT (AGENTS.md #3, #5):
    `proposed_risk` and `requires_approval` represent the LLM's OWN subjective suggestions
    and are STRICTLY ADVISORY. A future Policy Engine (Phase 2+) is the sole authority for
    final risk classification and approval requirements. Nothing in this codebase may treat
    these two fields as authoritative execution permissions.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    incident_id: str
    title: str
    description: str
    expected_effect: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    # LLM's OWN suggestion — ADVISORY ONLY. The Policy Engine is the sole authority for risk classification.
    proposed_risk: RemediationSafetyLevel
    # LLM's OWN suggestion — ADVISORY ONLY. The Policy Engine is the sole authority for approval requirements.
    requires_approval: bool
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ResetDemoFailureProposal(_RemediationProposalBase):
    """Proposal to reset the simulated fault injection state of the demo service."""

    action_type: Literal[ActionType.RESET_DEMO_FAILURE] = ActionType.RESET_DEMO_FAILURE
    parameters: ResetDemoFailureParameters = Field(default_factory=ResetDemoFailureParameters)


class RestartRegisteredServiceProposal(_RemediationProposalBase):
    """Proposal to trigger a controlled restart of the registered demo service."""

    action_type: Literal[ActionType.RESTART_REGISTERED_SERVICE] = (
        ActionType.RESTART_REGISTERED_SERVICE
    )
    parameters: RestartRegisteredServiceParameters = Field(
        default_factory=RestartRegisteredServiceParameters
    )


RemediationProposal = Annotated[
    ResetDemoFailureProposal | RestartRegisteredServiceProposal,
    Field(discriminator="action_type"),
]


# --- Post-Policy Validated Remediation Actions ---
class _RemediationActionBase(BaseModel):
    """Base schema for post-policy validated, executable remediation actions."""

    model_config = ConfigDict(frozen=True)

    id: str
    proposal_id: str
    policy_level: RemediationSafetyLevel  # authoritative — set ONLY by the future Policy Engine
    approval_required: bool  # authoritative — set ONLY by the future Policy Engine
    executor: str  # capability identifier, e.g. "demo_service.reset_failure_mode"


class ResetDemoFailureExecutableAction(_RemediationActionBase):
    """Executable action to reset demo service failure mode."""

    action_type: Literal[ActionType.RESET_DEMO_FAILURE] = ActionType.RESET_DEMO_FAILURE
    validated_parameters: ResetDemoFailureParameters


class RestartRegisteredServiceExecutableAction(_RemediationActionBase):
    """Executable action to restart the registered service."""

    action_type: Literal[ActionType.RESTART_REGISTERED_SERVICE] = (
        ActionType.RESTART_REGISTERED_SERVICE
    )
    validated_parameters: RestartRegisteredServiceParameters


RemediationAction = Annotated[
    ResetDemoFailureExecutableAction | RestartRegisteredServiceExecutableAction,
    Field(discriminator="action_type"),
]


# --- Execution Results ---
class RemediationExecutionStatus(StrEnum):
    """Status outcomes for remediation action execution."""

    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class RemediationResult(BaseModel):
    """Execution outcome recorded after running a validated remediation action."""

    model_config = ConfigDict(frozen=True)

    action_id: str
    status: RemediationExecutionStatus
    started_at: datetime
    completed_at: datetime | None = None
    success: bool
    summary: str
    error: str | None = None
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None


# --- Demo Service Response Schemas ---
class DemoServiceErrorModeResponse(BaseModel):
    """Response payload from demo service error mode endpoints."""

    model_config = ConfigDict(frozen=True)

    status: str
    error_mode: bool
    message: str


class DemoServiceHealthResponse(BaseModel):
    """Response payload from demo service health check endpoint."""

    model_config = ConfigDict(frozen=True)

    status: str
    service: str


# --- LLM Structured Output Models (Untrusted) ---
class RemediationActionCandidate(BaseModel):
    """Action candidate proposed by LLM (untrusted input requiring validation)."""

    name: str = Field(description="Short name for the recommended action")
    target_service: str = Field(description="Service targeted by this action")
    safety_level: int = Field(
        default=2,
        ge=0,
        le=2,
        description="Safety level: 0 (read-only), 1 (safe automatic), 2 (requires human approval)",
    )
    action_type: str = Field(
        description="Action identifier e.g. RESET_DEMO_FAILURE, RESTART_REGISTERED_SERVICE"
    )
    parameters: dict[str, Any] = Field(default_factory=dict)
    description: str = Field(description="Detailed explanation of what the action does")


class RemediationProposalResponse(BaseModel):
    """Structured proposal generated by LLM (untrusted input requiring validation)."""

    title: str = Field(description="Proposal title")
    summary: str = Field(description="Executive summary of why this remediation is proposed")
    actions: list[RemediationActionCandidate] = Field(
        default_factory=list, description="Recommended remediation actions"
    )
    estimated_impact: str = Field(
        default="", description="Expected outcome and recovery time after remediation"
    )
    rollback_plan: str = Field(
        default="", description="Steps to take if the remediation causes further degradation"
    )


# --- Validation Boundary ---
def parse_remediation_proposal(
    candidate: RemediationActionCandidate,
    *,
    incident_id: str,
    supporting_evidence_ids: list[str],
    expected_effect: str = "",
    title: str | None = None,
    requires_approval: bool = True,
) -> RemediationProposal:
    """Parse and validate an untrusted LLM candidate into a typed RemediationProposal variant.

    Raises ValueError or pydantic.ValidationError if candidate.action_type is unknown or parameters are invalid.
    """
    if candidate.safety_level == 0:
        proposed_risk = RemediationSafetyLevel.LEVEL_0_READ_ONLY
    elif candidate.safety_level == 1:
        proposed_risk = RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC
    else:
        proposed_risk = RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED

    raw_dict: dict[str, Any] = {
        "id": str(uuid4()),
        "incident_id": incident_id,
        "title": title or candidate.name,
        "description": candidate.description,
        "expected_effect": expected_effect,
        "supporting_evidence_ids": supporting_evidence_ids,
        "proposed_risk": proposed_risk,
        "requires_approval": requires_approval,
        "action_type": candidate.action_type,
        "parameters": candidate.parameters,
    }

    adapter: TypeAdapter[RemediationProposal] = TypeAdapter(RemediationProposal)
    return adapter.validate_python(raw_dict)


# --- Policy Decision Schemas ---
class PolicyDecisionType(StrEnum):
    """Authoritative decision outcomes emitted by the remediation policy engine."""

    ALLOWED = "ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    REJECTED = "REJECTED"


class AllowedAction(BaseModel):
    """Remediation action cleared for automatic execution under current policy."""

    model_config = ConfigDict(frozen=True)

    decision: Literal[PolicyDecisionType.ALLOWED] = PolicyDecisionType.ALLOWED
    action: RemediationAction


class ApprovalRequiredAction(BaseModel):
    """Remediation action requiring human operator approval before execution."""

    model_config = ConfigDict(frozen=True)

    decision: Literal[PolicyDecisionType.APPROVAL_REQUIRED] = PolicyDecisionType.APPROVAL_REQUIRED
    action: RemediationAction
    reason: str


class RejectedAction(BaseModel):
    """Remediation proposal rejected by policy engine constraints or allowlists."""

    model_config = ConfigDict(frozen=True)

    decision: Literal[PolicyDecisionType.REJECTED] = PolicyDecisionType.REJECTED
    proposal_id: str
    action_type: ActionType
    reason: str
    rejected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


PolicyResult = Annotated[
    AllowedAction | ApprovalRequiredAction | RejectedAction,
    Field(discriminator="decision"),
]


# --- Approval Schemas ---
class ApprovalDecision(StrEnum):
    """Operator decisions on a paused Level-2 remediation."""

    APPROVE = "APPROVE"
    REJECT = "REJECT"
    CANCEL = "CANCEL"


class ApprovalContext(BaseModel):
    """Everything an operator needs to decide on a paused Level-2 remediation — nothing more."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    incident_title: str
    root_cause_summary: str | None
    confidence: float | None
    action_type: ActionType
    action_parameters: dict[str, Any]
    policy_level: RemediationSafetyLevel
    expected_effect: str
    supporting_evidence_ids: list[str]
    reason_approval_required: str


# --- API Read Schemas ---
class RemediationResultRead(BaseModel):
    """API-facing read model for a persisted remediation execution result."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action_id: UUID
    status: RemediationExecutionStatus
    started_at: datetime
    completed_at: datetime | None
    success: bool
    summary: str
    error: str | None
    before_state: dict[str, Any] | None
    after_state: dict[str, Any] | None


class RemediationActionRead(BaseModel):
    """API-facing read model for a persisted remediation action and its approval lifecycle."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    proposal_id: UUID
    decision: PolicyDecisionType
    action_type: ActionType
    policy_level: RemediationSafetyLevel | None
    approval_required: bool | None
    executor: str | None
    validated_parameters: dict[str, Any] | None
    reason: str | None
    status: RemediationStatus
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    result: RemediationResultRead | None = None


class RemediationApprovalRequest(BaseModel):
    """Request body for approving or rejecting a paused remediation action."""

    approved_by: str = Field(
        default="operator",
        description="Free-text approver identifier — no authentication in v0.3.",
    )
