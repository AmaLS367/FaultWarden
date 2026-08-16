"""Remediation approval/rejection API routes.

No operator authentication in v0.3 — `approved_by` is a free-text identifier, not a verified
principal. A production deployment must add real authenticated/authorized approvers before these
endpoints are exposed beyond a trusted network.
"""

from uuid import UUID

from fastapi import APIRouter, Depends

from faultwarden.api.dependencies import (
    get_incident_service,
    get_investigation_service,
    get_remediation_audit_service,
)
from faultwarden.core.exceptions import (
    RemediationActionNotFoundError,
    RemediationNotAwaitingApprovalError,
)
from faultwarden.db.models.remediation import RemediationActionModel
from faultwarden.schemas.remediation import (
    ApprovalDecision,
    RemediationActionRead,
    RemediationApprovalRequest,
    RemediationResultRead,
    RemediationStatus,
    RemediationValidationRead,
)
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService
from faultwarden.services.remediation_audit_service import RemediationAuditService

router = APIRouter(prefix="/incidents", tags=["Remediations"])


# --- Response Assembly ---
async def _build_action_read(
    action: RemediationActionModel, audit_service: RemediationAuditService
) -> RemediationActionRead:
    """Attach an action's execution result and recovery validation (if any) and build the API read model."""
    action_read = RemediationActionRead.model_validate(action)
    result = await audit_service.get_result_for_action(action.id)
    if result is not None:
        action_read = action_read.model_copy(
            update={"result": RemediationResultRead.model_validate(result)}
        )
    validation = await audit_service.get_validation_for_action(action.id)
    if validation is not None:
        action_read = action_read.model_copy(
            update={"validation": RemediationValidationRead.model_validate(validation)}
        )
    return action_read


async def _get_action_or_404(
    incident_id: UUID, remediation_id: UUID, audit_service: RemediationAuditService
) -> RemediationActionModel:
    """Fetch a remediation action scoped to its incident, or raise 404 (never leak cross-incident existence)."""
    action = await audit_service.get_action(remediation_id)
    if action is None or action.incident_id != incident_id:
        raise RemediationActionNotFoundError(str(remediation_id))
    return action


# --- Query Routes ---
@router.get(
    "/{incident_id}/remediations",
    response_model=list[RemediationActionRead],
    summary="List Incident Remediations",
    description="List all remediation actions (policy decisions and their approval lifecycle) for an incident.",
)
async def list_incident_remediations(
    incident_id: UUID,
    incident_service: IncidentService = Depends(get_incident_service),
    audit_service: RemediationAuditService = Depends(get_remediation_audit_service),
) -> list[RemediationActionRead]:
    """List remediation actions for an incident."""
    await incident_service.get_incident(incident_id)
    actions = await audit_service.list_actions_for_incident(incident_id)
    return [await _build_action_read(action, audit_service) for action in actions]


@router.get(
    "/{incident_id}/remediations/{remediation_id}",
    response_model=RemediationActionRead,
    summary="Get Remediation Action",
    description="Fetch a single remediation action, including its execution result if one exists.",
)
async def get_incident_remediation(
    incident_id: UUID,
    remediation_id: UUID,
    audit_service: RemediationAuditService = Depends(get_remediation_audit_service),
) -> RemediationActionRead:
    """Get a single remediation action by ID, scoped to its incident."""
    action = await _get_action_or_404(incident_id, remediation_id, audit_service)
    return await _build_action_read(action, audit_service)


# --- Approval/Rejection Routes ---
@router.post(
    "/{incident_id}/remediations/{remediation_id}/approve",
    response_model=RemediationActionRead,
    summary="Approve Remediation",
    description=(
        "Approve a paused Level-2 remediation and resume the investigation workflow to execute "
        "it. Approves the exact validated action only — modified parameters are not accepted; "
        "generate a new proposal instead. No operator authentication in v0.3."
    ),
)
async def approve_incident_remediation(
    incident_id: UUID,
    remediation_id: UUID,
    body: RemediationApprovalRequest,
    audit_service: RemediationAuditService = Depends(get_remediation_audit_service),
    investigation_service: InvestigationService = Depends(get_investigation_service),
) -> RemediationActionRead:
    """Approve a paused remediation action and resume graph execution."""
    action = await _get_action_or_404(incident_id, remediation_id, audit_service)
    if action.status != RemediationStatus.AWAITING_APPROVAL:
        raise RemediationNotAwaitingApprovalError(
            str(incident_id),
            current_status=action.status.value
            if hasattr(action.status, "value")
            else str(action.status),
        )

    await investigation_service.resume_remediation_approval(
        incident_id, decision=ApprovalDecision.APPROVE, approved_by=body.approved_by
    )

    updated_action = await _get_action_or_404(incident_id, remediation_id, audit_service)
    return await _build_action_read(updated_action, audit_service)


@router.post(
    "/{incident_id}/remediations/{remediation_id}/reject",
    response_model=RemediationActionRead,
    summary="Reject Remediation",
    description="Reject a paused Level-2 remediation. The action is never executed. No operator authentication in v0.3.",
)
async def reject_incident_remediation(
    incident_id: UUID,
    remediation_id: UUID,
    body: RemediationApprovalRequest,
    audit_service: RemediationAuditService = Depends(get_remediation_audit_service),
    investigation_service: InvestigationService = Depends(get_investigation_service),
) -> RemediationActionRead:
    """Reject a paused remediation action and resume graph execution without executing it."""
    action = await _get_action_or_404(incident_id, remediation_id, audit_service)
    if action.status != RemediationStatus.AWAITING_APPROVAL:
        raise RemediationNotAwaitingApprovalError(
            str(incident_id),
            current_status=action.status.value
            if hasattr(action.status, "value")
            else str(action.status),
        )

    await investigation_service.resume_remediation_approval(
        incident_id, decision=ApprovalDecision.REJECT, approved_by=body.approved_by
    )

    updated_action = await _get_action_or_404(incident_id, remediation_id, audit_service)
    return await _build_action_read(updated_action, audit_service)
