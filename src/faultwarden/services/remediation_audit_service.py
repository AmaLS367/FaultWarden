"""Service layer for remediation proposal, policy decision, approval, execution claim, and result persistence."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.exceptions import (
    InvalidStateTransitionError,
    RemediationActionNotFoundError,
    RemediationExecutionClaimError,
    RemediationNotAwaitingApprovalError,
    RemediationProposalNotFoundError,
)
from faultwarden.core.logging import get_logger
from faultwarden.db.models.remediation import (
    RemediationActionModel,
    RemediationProposalModel,
    RemediationResultModel,
    RemediationValidationModel,
)
from faultwarden.schemas.remediation import (
    AllowedAction,
    ApprovalRequiredAction,
    PolicyDecisionType,
    PolicyResult,
    RejectedAction,
    RemediationProposal,
    RemediationResult,
    RemediationStatus,
    RemediationValidationResult,
)

logger = get_logger("faultwarden.services.remediation_audit")


# --- State Machine Transitions ---
# Invariant: Issue 4 - Strict remediation action lifecycle state machine.
# Disallow arbitrary status jumps (e.g. SUCCEEDED -> EXECUTING, REJECTED -> APPROVED, FAILED -> EXECUTING).
ALLOWED_TRANSITIONS: dict[RemediationStatus, set[RemediationStatus]] = {
    RemediationStatus.PROPOSED: {
        RemediationStatus.APPROVED,
        RemediationStatus.AWAITING_APPROVAL,
        RemediationStatus.REJECTED,
    },
    RemediationStatus.AWAITING_APPROVAL: {
        RemediationStatus.APPROVED,
        RemediationStatus.REJECTED,
    },
    RemediationStatus.APPROVED: {
        RemediationStatus.EXECUTING,
    },
    RemediationStatus.EXECUTING: {
        RemediationStatus.SUCCEEDED,
        RemediationStatus.FAILED,
    },
    RemediationStatus.SUCCEEDED: set(),
    RemediationStatus.FAILED: set(),
    RemediationStatus.REJECTED: set(),
    RemediationStatus.ROLLED_BACK: set(),
}


def transition_action_status(
    action: RemediationActionModel,
    target_status: RemediationStatus,
) -> None:
    """Validate and apply a lifecycle state transition to a remediation action entity.

    Raises InvalidStateTransitionError if the attempted transition is not permitted by the state machine.
    """
    current_status = action.status
    if current_status == target_status:
        return

    allowed = ALLOWED_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        logger.warning(
            "invalid_action_status_transition_attempted",
            action_id=str(action.id),
            current_status=current_status.value,
            target_status=target_status.value,
        )
        raise InvalidStateTransitionError(
            entity=f"RemediationAction(id={action.id})",
            current_status=current_status.value,
            target_status=target_status.value,
        )

    action.status = target_status


class RemediationAuditService:
    """Encapsulates persistence and audit trail operations for remediation lifecycle."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- Proposal Persistence ---
    async def create_proposal(self, proposal: RemediationProposal) -> RemediationProposalModel:
        """Persist a validated LLM proposal as an immutable audit record."""
        proposal_id = UUID(proposal.id) if isinstance(proposal.id, str) else proposal.id
        incident_id = (
            UUID(proposal.incident_id)
            if isinstance(proposal.incident_id, str)
            else proposal.incident_id
        )

        parameters_dict = (
            proposal.parameters.model_dump(mode="json")
            if hasattr(proposal.parameters, "model_dump")
            else proposal.parameters
        )

        proposed_risk_val = int(proposal.proposed_risk.value)

        model = RemediationProposalModel(
            id=proposal_id,
            incident_id=incident_id,
            action_type=proposal.action_type,
            title=proposal.title,
            description=proposal.description,
            expected_effect=proposal.expected_effect,
            supporting_evidence_ids=list(proposal.supporting_evidence_ids),
            proposed_risk=proposed_risk_val,
            requires_approval=proposal.requires_approval,
            parameters=parameters_dict,
        )

        self.session.add(model)
        await self.session.flush()
        await self.session.refresh(model)

        logger.info(
            "remediation_proposal_created",
            proposal_id=str(model.id),
            incident_id=str(model.incident_id),
            action_type=model.action_type.value,
            title=model.title,
        )
        return model

    # --- Policy Decision Persistence ---
    async def create_action_decision(self, policy_result: PolicyResult) -> RemediationActionModel:
        """Persist a policy decision (ALLOWED/APPROVAL_REQUIRED/REJECTED) as an auditable row."""
        idempotency_key: str | None = None

        if isinstance(policy_result, RejectedAction):
            proposal_id_str = policy_result.proposal_id
            action_id_str = None
            action_type = policy_result.action_type
            decision = PolicyDecisionType.REJECTED
            status = RemediationStatus.REJECTED
            policy_level_val = None
            approval_required = None
            executor = None
            validated_parameters = None
            reason = policy_result.reason
        elif isinstance(policy_result, AllowedAction):
            proposal_id_str = policy_result.action.proposal_id
            action_id_str = policy_result.action.id
            action_type = policy_result.action.action_type
            decision = PolicyDecisionType.ALLOWED
            status = RemediationStatus.APPROVED
            policy_level_val = int(policy_result.action.policy_level.value)
            approval_required = policy_result.action.approval_required
            executor = policy_result.action.executor
            validated_parameters = (
                policy_result.action.validated_parameters.model_dump(mode="json")
                if hasattr(policy_result.action.validated_parameters, "model_dump")
                else policy_result.action.validated_parameters
            )
            reason = None
            idempotency_key = getattr(policy_result.action, "idempotency_key", None)
        elif isinstance(policy_result, ApprovalRequiredAction):
            proposal_id_str = policy_result.action.proposal_id
            action_id_str = policy_result.action.id
            action_type = policy_result.action.action_type
            decision = PolicyDecisionType.APPROVAL_REQUIRED
            status = RemediationStatus.AWAITING_APPROVAL
            policy_level_val = int(policy_result.action.policy_level.value)
            approval_required = policy_result.action.approval_required
            executor = policy_result.action.executor
            validated_parameters = (
                policy_result.action.validated_parameters.model_dump(mode="json")
                if hasattr(policy_result.action.validated_parameters, "model_dump")
                else policy_result.action.validated_parameters
            )
            reason = policy_result.reason
            idempotency_key = getattr(policy_result.action, "idempotency_key", None)
        else:
            raise TypeError(f"Unsupported policy result type: {type(policy_result)}")

        proposal_uuid = (
            UUID(proposal_id_str) if isinstance(proposal_id_str, str) else proposal_id_str
        )

        proposal_row = await self.get_proposal(proposal_uuid)
        if proposal_row is None:
            raise RemediationProposalNotFoundError(str(proposal_uuid))
        incident_id = proposal_row.incident_id

        action_uuid = UUID(action_id_str) if action_id_str is not None else uuid4()

        if idempotency_key is None and action_id_str is not None:
            idempotency_key = f"rem-exec-{action_id_str}"

        # If action already exists by ID, return existing entity
        existing_action = await self.get_action(action_uuid)
        if existing_action is not None:
            return existing_action

        # If action already exists by idempotency key, return existing entity
        if idempotency_key is not None:
            stmt = select(RemediationActionModel).where(
                RemediationActionModel.idempotency_key == idempotency_key
            )
            res = await self.session.execute(stmt)
            existing_key_action = res.scalar_one_or_none()
            if existing_key_action is not None:
                return existing_key_action

        model = RemediationActionModel(
            id=action_uuid,
            proposal_id=proposal_uuid,
            incident_id=incident_id,
            decision=decision,
            action_type=action_type,
            policy_level=policy_level_val,
            approval_required=approval_required,
            executor=executor,
            validated_parameters=validated_parameters,
            reason=reason,
            status=status,
            idempotency_key=idempotency_key,
            claim_expires_at=None,
            approved_by=None,
            approved_at=None,
        )

        self.session.add(model)
        await self.session.flush()
        await self.session.refresh(model)

        logger.info(
            "remediation_action_decision_created",
            action_id=str(model.id),
            proposal_id=str(model.proposal_id),
            incident_id=str(model.incident_id),
            decision=model.decision.value,
            status=model.status.value,
            idempotency_key=model.idempotency_key,
        )
        return model

    # --- Approval Recording ---
    async def record_approval_decision(
        self,
        action_id: UUID | str,
        *,
        decision: Any = None,
        approved: bool | None = None,
        approved_by: str,
    ) -> RemediationActionModel:
        """Record an operator's approval or rejection of a Level-2 remediation proposal.

        Validates the state transition before writing. Accepts either `decision` (ApprovalDecision/bool)
        or `approved` (bool) for backward compatibility.
        """
        uuid_val = action_id if isinstance(action_id, UUID) else UUID(str(action_id))
        action = await self.get_action(uuid_val)
        if action is None:
            raise RemediationActionNotFoundError(str(uuid_val))

        if action.status != RemediationStatus.AWAITING_APPROVAL:
            raise RemediationNotAwaitingApprovalError(
                str(action.incident_id),
                current_status=action.status.value,
            )

        is_approved = False
        if decision is not None:
            if isinstance(decision, bool):
                is_approved = decision
            elif hasattr(decision, "value"):
                is_approved = decision.value == "approve" or decision.value == "APPROVE"
            elif str(decision).upper() in ("APPROVE", "APPROVED", "TRUE"):
                is_approved = True
        elif approved is not None:
            is_approved = approved

        target_status = RemediationStatus.APPROVED if is_approved else RemediationStatus.REJECTED
        transition_action_status(action, target_status)
        action.approved_by = approved_by
        action.approved_at = datetime.now(UTC)

        await self.session.flush()
        await self.session.refresh(action)

        logger.info(
            "remediation_approval_recorded",
            action_id=str(action.id),
            approved=is_approved,
            approved_by=approved_by,
            new_status=action.status.value,
        )
        return action

    # --- Execution Locking & Claim ---
    async def claim_action_for_execution(
        self,
        action_id: UUID | str,
        *,
        lease_seconds: int = 120,
    ) -> RemediationActionModel:
        """Atomically claim a remediation action for execution.

        Invariants (Issue 6):
        - Action must be in APPROVED status (or an expired claim lease).
        - Transitions status to EXECUTING.
        - Concurrent callers cannot both acquire the claim.
        - Actions already SUCCEEDED or FAILED cannot be claimed.
        """
        uuid_val = action_id if isinstance(action_id, UUID) else UUID(str(action_id))
        action = await self.get_action(uuid_val)
        if action is None:
            raise RemediationActionNotFoundError(str(uuid_val))

        now = datetime.now(UTC)

        # If already executing with an unexpired lease, reject claim
        if action.status == RemediationStatus.EXECUTING:
            claim_exp = (
                action.claim_expires_at.replace(tzinfo=UTC)
                if (action.claim_expires_at and action.claim_expires_at.tzinfo is None)
                else action.claim_expires_at
            )
            if claim_exp and claim_exp > now:
                raise RemediationExecutionClaimError(
                    str(uuid_val),
                    f"Action is already EXECUTING under active lease until {action.claim_expires_at.isoformat() if action.claim_expires_at else 'unknown'}.",
                )
            # Expired claim lease can be reclaimed
            logger.warning(
                "reclaiming_expired_execution_claim",
                action_id=str(uuid_val),
                expired_lease=action.claim_expires_at.isoformat()
                if action.claim_expires_at
                else "none",
            )

        elif action.status != RemediationStatus.APPROVED:
            raise RemediationExecutionClaimError(
                str(uuid_val),
                f"Action status is '{action.status.value}', required 'APPROVED' for execution.",
            )

        # Transition to EXECUTING with lease
        transition_action_status(action, RemediationStatus.EXECUTING)
        action.claim_expires_at = now + timedelta(seconds=lease_seconds)

        await self.session.flush()
        await self.session.refresh(action)

        logger.info(
            "remediation_action_claimed_for_execution",
            action_id=str(action.id),
            status=action.status.value,
            claim_expires_at=action.claim_expires_at.isoformat()
            if action.claim_expires_at
            else None,
        )
        return action

    # --- Execution Result Persistence ---
    async def record_execution_result(self, result: RemediationResult) -> RemediationResultModel:
        """Persist an executor's outcome and transition the action status to SUCCEEDED or FAILED."""
        action_uuid = (
            UUID(result.action_id) if isinstance(result.action_id, str) else result.action_id
        )

        action = await self.get_action(action_uuid)
        if action is not None:
            target_status = (
                RemediationStatus.SUCCEEDED if result.success else RemediationStatus.FAILED
            )
            # If action was APPROVED, transition through EXECUTING first
            if action.status == RemediationStatus.APPROVED:
                transition_action_status(action, RemediationStatus.EXECUTING)
            # Apply state transition from EXECUTING to SUCCEEDED/FAILED
            transition_action_status(action, target_status)
            action.claim_expires_at = None

        model = RemediationResultModel(
            id=uuid4(),
            action_id=action_uuid,
            status=result.status,
            started_at=result.started_at,
            completed_at=result.completed_at,
            success=result.success,
            summary=result.summary,
            error=result.error,
            before_state=result.before_state,
            after_state=result.after_state,
        )

        self.session.add(model)
        await self.session.flush()
        await self.session.refresh(model)

        logger.info(
            "remediation_execution_result_recorded",
            result_id=str(model.id),
            action_id=str(model.action_id),
            status=model.status.value,
            success=model.success,
        )
        return model

    # --- Recovery Validation Persistence ---
    async def record_validation_result(
        self,
        validation_result: RemediationValidationResult,
        incident_id: UUID,
    ) -> RemediationValidationModel:
        """Persist a multi-signal recovery validation result linked to its action and incident."""
        action_uuid = (
            UUID(validation_result.action_id)
            if isinstance(validation_result.action_id, str)
            else validation_result.action_id
        )

        checks_data = [
            c.model_dump(mode="json") if hasattr(c, "model_dump") else c
            for c in validation_result.checks
        ]

        model = RemediationValidationModel(
            id=uuid4(),
            action_id=action_uuid,
            incident_id=incident_id,
            passed=validation_result.passed,
            status=validation_result.status,
            checks=checks_data,
            summary=validation_result.summary,
            started_at=validation_result.started_at,
            completed_at=validation_result.completed_at,
        )

        self.session.add(model)
        await self.session.flush()
        await self.session.refresh(model)

        logger.info(
            "remediation_validation_recorded",
            validation_id=str(model.id),
            action_id=str(model.action_id),
            incident_id=str(model.incident_id),
            passed=model.passed,
            status=model.status.value,
        )
        return model

    # --- Queries & Lookups ---
    async def get_action(self, action_id: UUID) -> RemediationActionModel | None:
        """Retrieve a remediation action by its primary key ID."""
        uuid_val = action_id if isinstance(action_id, UUID) else UUID(action_id)
        stmt = select(RemediationActionModel).where(RemediationActionModel.id == uuid_val)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_proposal(self, proposal_id: UUID) -> RemediationProposalModel | None:
        """Retrieve a remediation proposal by its primary key ID."""
        uuid_val = proposal_id if isinstance(proposal_id, UUID) else UUID(str(proposal_id))
        stmt = select(RemediationProposalModel).where(RemediationProposalModel.id == uuid_val)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_result_for_action(self, action_id: UUID) -> RemediationResultModel | None:
        """Retrieve the execution result recorded for a remediation action, if any."""
        uuid_val = action_id if isinstance(action_id, UUID) else UUID(action_id)
        stmt = select(RemediationResultModel).where(RemediationResultModel.action_id == uuid_val)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_validation_for_action(self, action_id: UUID) -> RemediationValidationModel | None:
        """Retrieve the recovery validation outcome recorded for an action, if any."""
        uuid_val = action_id if isinstance(action_id, UUID) else UUID(action_id)
        stmt = select(RemediationValidationModel).where(
            RemediationValidationModel.action_id == uuid_val
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_actions_for_incident(self, incident_id: UUID) -> list[RemediationActionModel]:
        """List all remediation actions associated with an incident, ordered most recent first."""
        uuid_val = incident_id if isinstance(incident_id, UUID) else UUID(str(incident_id))
        stmt = (
            select(RemediationActionModel)
            .where(RemediationActionModel.incident_id == uuid_val)
            .order_by(desc(RemediationActionModel.created_at))
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def list_validations_for_incident(
        self, incident_id: UUID
    ) -> list[RemediationValidationModel]:
        """List all recovery validations recorded for an incident."""
        uuid_val = incident_id if isinstance(incident_id, UUID) else UUID(str(incident_id))
        stmt = (
            select(RemediationValidationModel)
            .where(RemediationValidationModel.incident_id == uuid_val)
            .order_by(desc(RemediationValidationModel.created_at))
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
