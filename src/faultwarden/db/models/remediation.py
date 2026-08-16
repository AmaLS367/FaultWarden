"""SQLAlchemy ORM models for remediation lifecycle, validation, and audit trail."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column

from faultwarden.db.base import GUID, Base, TimestampMixin
from faultwarden.schemas.remediation import (
    ActionType,
    PolicyDecisionType,
    RemediationExecutionStatus,
    RemediationStatus,
    RemediationValidationStatus,
)


# --- Remediation Proposal Model ---
class RemediationProposalModel(Base, TimestampMixin):
    """Database model for pre-policy LLM remediation proposals."""

    __tablename__ = "remediation_proposals"

    # --- Core Identifiers ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    incident_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )

    # --- Proposal Attributes ---
    action_type: Mapped[ActionType] = mapped_column(
        SQLEnum(ActionType, name="remediation_action_type", native_enum=False),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    expected_effect: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # LLM's own suggestion — audit only, never authoritative
    proposed_risk: Mapped[int] = mapped_column(Integer, nullable=False)

    # LLM's own suggestion — audit only
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<RemediationProposalModel(id={self.id}, incident_id={self.incident_id}, "
            f"action_type='{self.action_type}', title='{self.title}')>"
        )


# --- Remediation Action Model ---
class RemediationActionModel(Base, TimestampMixin):
    """Database model for post-policy remediation actions, execution claims, and approval lifecycle."""

    __tablename__ = "remediation_actions"

    # --- Core Identifiers ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    proposal_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("remediation_proposals.id"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )

    # --- Policy Decision & Execution Specs ---
    decision: Mapped[PolicyDecisionType] = mapped_column(
        SQLEnum(PolicyDecisionType, name="policy_decision_type", native_enum=False),
        nullable=False,
    )
    action_type: Mapped[ActionType] = mapped_column(
        SQLEnum(ActionType, name="remediation_action_type", native_enum=False),
        nullable=False,
    )
    policy_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    approval_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    executor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    validated_parameters: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Durable Idempotency & Execution Claim ---
    idempotency_key: Mapped[str | None] = mapped_column(
        String(100), unique=True, nullable=True, index=True
    )
    claim_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # --- Approval Lifecycle & Status ---
    status: Mapped[RemediationStatus] = mapped_column(
        SQLEnum(RemediationStatus, name="remediation_status", native_enum=False),
        nullable=False,
    )
    approved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<RemediationActionModel(id={self.id}, proposal_id={self.proposal_id}, "
            f"decision='{self.decision}', status='{self.status}')>"
        )


# --- Remediation Result Model ---
class RemediationResultModel(Base, TimestampMixin):
    """Database model for remediation execution outcome."""

    __tablename__ = "remediation_results"

    # --- Core Identifiers ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    action_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("remediation_actions.id"),
        unique=True,
        nullable=False,
        index=True,
    )

    # --- Execution Status & Telemetry ---
    status: Mapped[RemediationExecutionStatus] = mapped_column(
        SQLEnum(RemediationExecutionStatus, name="remediation_execution_status", native_enum=False),
        nullable=False,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<RemediationResultModel(id={self.id}, action_id={self.action_id}, "
            f"status='{self.status}', success={self.success})>"
        )


# --- Remediation Validation Model ---
class RemediationValidationModel(Base, TimestampMixin):
    """Database model for multi-signal deterministic recovery validation outcome."""

    __tablename__ = "remediation_validations"

    # --- Core Identifiers ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    action_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("remediation_actions.id"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )

    # --- Validation Results ---
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[RemediationValidationStatus] = mapped_column(
        SQLEnum(
            RemediationValidationStatus,
            name="remediation_validation_status",
            native_enum=False,
        ),
        nullable=False,
    )
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<RemediationValidationModel(id={self.id}, action_id={self.action_id}, "
            f"passed={self.passed}, status='{self.status}')>"
        )
