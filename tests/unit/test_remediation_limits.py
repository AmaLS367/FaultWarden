"""Unit tests for remediation attempt/auto-execution limits and stale-approval handling (v0.3 Phase 13-14)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.exceptions import RemediationApprovalStaleError
from faultwarden.graph.nodes.remediation_policy import evaluate_remediation_policy_node
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.incident import IncidentCreate, IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import (
    AllowedAction,
    ApprovalDecision,
    PolicyDecisionType,
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
)
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService
from faultwarden.services.remediation_audit_service import RemediationAuditService


def _make_proposal(incident_id: str) -> ResetDemoFailureProposal:
    return ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=incident_id,
        title="Reset Demo Failure",
        description="Reset error injection flag",
        expected_effect="200 OK restored",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=True,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )


def _base_state(incident_id: str, proposal: ResetDemoFailureProposal) -> IncidentInvestigationState:
    return {
        "incident_id": incident_id,
        "incident_context": {"service": "demo-service"},
        "alert": {},
        "classification": None,
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [proposal],
        "iteration_count": 1,
        "missing_evidence_queries": [],
        "investigation_status": "INVESTIGATING",
        "summary": "",
        "errors": [],
    }


@pytest.mark.asyncio
async def test_max_attempts_reached_rejects_regardless_of_underlying_decision() -> None:
    """1. prior_attempt_count >= max_remediation_attempts_per_incident forces REJECTED."""
    proposal = _make_proposal("inc-limits-1")
    state = _base_state("inc-limits-1", proposal)
    state["remediation_prior_attempt_count"] = 3  # matches RemediationSettings default
    state["remediation_prior_auto_execution_count"] = 0

    result = await evaluate_remediation_policy_node(state, config=None)
    policy_result = result["remediation_policy_result"]

    assert policy_result.decision == PolicyDecisionType.REJECTED
    assert "Maximum remediation attempts" in policy_result.reason


@pytest.mark.asyncio
async def test_max_auto_executions_reached_rejects_only_allowed_decision() -> None:
    """2. prior_auto_execution_count >= max_auto_remediations_per_incident forces REJECTED for what would be ALLOWED."""
    proposal = _make_proposal("inc-limits-2")
    state = _base_state("inc-limits-2", proposal)
    state["remediation_prior_attempt_count"] = 0
    state["remediation_prior_auto_execution_count"] = 1  # matches RemediationSettings default

    result = await evaluate_remediation_policy_node(state, config=None)
    policy_result = result["remediation_policy_result"]

    # RESET_DEMO_FAILURE at LEVEL_1 with default settings would normally be ALLOWED.
    assert policy_result.decision == PolicyDecisionType.REJECTED
    assert "Maximum auto-executed remediations" in policy_result.reason


@pytest.mark.asyncio
async def test_under_limits_proceeds_normally() -> None:
    """3. Counts below both limits leave the underlying policy decision untouched."""
    proposal = _make_proposal("inc-limits-3")
    state = _base_state("inc-limits-3", proposal)
    state["remediation_prior_attempt_count"] = 0
    state["remediation_prior_auto_execution_count"] = 0

    result = await evaluate_remediation_policy_node(state, config=None)
    policy_result = result["remediation_policy_result"]

    assert policy_result.decision == PolicyDecisionType.ALLOWED


@pytest.mark.asyncio
async def test_run_investigation_stops_automation_after_max_attempts(
    db_session: AsyncSession,
) -> None:
    """4. run_investigation rejects a new proposal once the incident already has max_remediation_attempts_per_incident prior actions on record."""
    incident_service = IncidentService(session=db_session)
    audit_service = RemediationAuditService(session=db_session)
    mock_executor = AsyncMock()
    investigation_service = InvestigationService(
        incident_service=incident_service,
        remediation_executor=mock_executor,
        remediation_validator=AsyncMock(return_value=True),
    )

    create_dto = IncidentCreate(
        title="[CRITICAL] Limits test incident",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint="fp-limits-max-attempts",
        service="demo-service",
        alert_status="firing",
        alert_payload={},
    )
    incident = await incident_service.create_incident(create_dto)

    # Pre-seed 3 prior actions (any decision) to hit the default max_remediation_attempts_per_incident=3,
    # regardless of which decision type this run's primary proposal would otherwise receive.
    for _ in range(3):
        prior_proposal = _make_proposal(str(incident.id))
        await audit_service.create_proposal(prior_proposal)
        await audit_service.create_action_decision(
            AllowedAction(
                action=ResetDemoFailureExecutableAction(
                    id=str(uuid4()),
                    proposal_id=prior_proposal.id,
                    policy_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
                    approval_required=False,
                    executor="demo_service.reset_failure_mode",
                    validated_parameters=ResetDemoFailureParameters(service="demo-service"),
                )
            )
        )
    await db_session.commit()

    updated_incident = await investigation_service.run_investigation(incident.id)

    actions = await audit_service.list_actions_for_incident(incident.id)
    newest = max(actions, key=lambda a: a.created_at)
    assert newest.decision == PolicyDecisionType.REJECTED
    assert "Maximum remediation attempts" in (newest.reason or "")
    mock_executor.assert_not_called()
    assert updated_incident.status != IncidentStatus.RESOLVED
    assert updated_incident.status != IncidentStatus.AWAITING_APPROVAL


@pytest.mark.asyncio
async def test_resume_stale_approval_raises_and_does_not_execute(
    db_session: AsyncSession,
) -> None:
    """5. resume_remediation_approval on a stale (past approval_timeout_seconds) action raises and executes nothing."""
    incident_service = IncidentService(session=db_session)
    mock_executor = AsyncMock()
    investigation_service = InvestigationService(
        incident_service=incident_service,
        remediation_executor=mock_executor,
        remediation_validator=AsyncMock(return_value=True),
    )

    create_dto = IncidentCreate(
        title="[CRITICAL] Stale approval test incident",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint="fp-limits-stale",
        service="demo-service",
        alert_status="firing",
        alert_payload={},
    )
    incident = await incident_service.create_incident(create_dto)
    await investigation_service.run_investigation(incident.id)

    audit_service = RemediationAuditService(session=db_session)
    actions = await audit_service.list_actions_for_incident(incident.id)
    awaiting = [a for a in actions if a.status.value == "AWAITING_APPROVAL"]
    assert len(awaiting) == 1
    action = awaiting[0]

    # Artificially age the action past the default 86400s approval timeout.
    action.created_at = datetime.now(UTC) - timedelta(seconds=90000)
    await db_session.flush()

    with pytest.raises(RemediationApprovalStaleError):
        await investigation_service.resume_remediation_approval(
            incident.id,
            decision=ApprovalDecision.APPROVE,
            approved_by="operator-test",
        )

    mock_executor.assert_not_called()
    refreshed = await audit_service.get_action(action.id)
    assert refreshed is not None
    assert refreshed.status.value == "AWAITING_APPROVAL"
