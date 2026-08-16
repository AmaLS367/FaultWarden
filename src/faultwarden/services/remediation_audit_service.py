"""Service layer for remediation proposal, policy decision, approval, and result persistence."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.exceptions import (
    RemediationActionNotFoundError,
    RemediationProposalNotFoundError,
)
from faultwarden.core.logging import get_logger
from faultwarden.db.models.remediation import (
    RemediationActionModel,
    RemediationProposalModel,
    RemediationResultModel,
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
)

logger = get_logger("faultwarden.services.remediation_audit")


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

        proposed_risk_val = (
            int(proposal.proposed_risk.value)
            if hasattr(proposal.proposed_risk, "value")
            else int(proposal.proposed_risk)
        )

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
            action_type=model.action_type.value
            if hasattr(model.action_type, "value")
            else str(model.action_type),
            title=model.title,
        )
        return model

    # --- Policy Decision Persistence ---
    async def create_action_decision(self, policy_result: PolicyResult) -> RemediationActionModel:
        """Persist a policy decision (ALLOWED/APPROVAL_REQUIRED/REJECTED) as an auditable row."""
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
            policy_level_val = (
                int(policy_result.action.policy_level.value)
                if hasattr(policy_result.action.policy_level, "value")
                else int(policy_result.action.policy_level)
            )
            approval_required = policy_result.action.approval_required
            executor = policy_result.action.executor
            validated_parameters = (
                policy_result.action.validated_parameters.model_dump(mode="json")
                if hasattr(policy_result.action.validated_parameters, "model_dump")
                else policy_result.action.validated_parameters
            )
            reason = None
        elif isinstance(policy_result, ApprovalRequiredAction):
            proposal_id_str = policy_result.action.proposal_id
            action_id_str = policy_result.action.id
            action_type = policy_result.action.action_type
            decision = PolicyDecisionType.APPROVAL_REQUIRED
            status = RemediationStatus.AWAITING_APPROVAL
            policy_level_val = (
                int(policy_result.action.policy_level.value)
                if hasattr(policy_result.action.policy_level, "value")
                else int(policy_result.action.policy_level)
            )
            approval_required = policy_result.action.approval_required
            executor = policy_result.action.executor
            validated_parameters = (
                policy_result.action.validated_parameters.model_dump(mode="json")
                if hasattr(policy_result.action.validated_parameters, "model_dump")
                else policy_result.action.validated_parameters
            )
            reason = policy_result.reason
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
            decision=model.decision.value
            if hasattr(model.decision, "value")
            else str(model.decision),
            status=model.status.value if hasattr(model.status, "value") else str(model.status),
        )
        return model

    # --- Approval Lifecycle Persistence ---
    async def record_approval_decision(
        self, action_id: UUID, *, approved: bool, approved_by: str
    ) -> RemediationActionModel:
        """Record a human approve/reject decision and update status accordingly."""
        action = await self.get_action(action_id)
        if action is None:
            raise RemediationActionNotFoundError(str(action_id))

        action.status = RemediationStatus.APPROVED if approved else RemediationStatus.REJECTED
        action.approved_by = approved_by
        action.approved_at = datetime.now(UTC)

        await self.session.flush()
        await self.session.refresh(action)

        logger.info(
            "remediation_approval_recorded",
            action_id=str(action.id),
            approved=approved,
            approved_by=approved_by,
            new_status=action.status.value
            if hasattr(action.status, "value")
            else str(action.status),
        )
        return action

    # --- Execution Result Persistence ---
    async def record_execution_result(self, result: RemediationResult) -> RemediationResultModel:
        """Persist an executor's outcome."""
        action_uuid = (
            UUID(result.action_id) if isinstance(result.action_id, str) else result.action_id
        )

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
            status=model.status.value if hasattr(model.status, "value") else str(model.status),
            success=model.success,
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
        uuid_val = proposal_id if isinstance(proposal_id, UUID) else UUID(proposal_id)
        stmt = select(RemediationProposalModel).where(RemediationProposalModel.id == uuid_val)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_actions_for_incident(self, incident_id: UUID) -> list[RemediationActionModel]:
        """List all remediation actions associated with an incident, ordered most recent first."""
        uuid_val = incident_id if isinstance(incident_id, UUID) else UUID(incident_id)
        stmt = (
            select(RemediationActionModel)
            .where(RemediationActionModel.incident_id == uuid_val)
            .order_by(desc(RemediationActionModel.created_at))
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())
