"""Unit tests for RemediationAuditService persistence and lifecycle."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.config import RemediationSettings
from faultwarden.core.exceptions import (
    RemediationActionNotFoundError,
    RemediationProposalNotFoundError,
)
from faultwarden.core.policy import evaluate_policy
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.remediation import (
    RemediationActionModel,
)
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import (
    ActionType,
    AllowedAction,
    ApprovalRequiredAction,
    PolicyDecisionType,
    RejectedAction,
    RemediationExecutionStatus,
    RemediationResult,
    RemediationSafetyLevel,
    RemediationStatus,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
    RestartRegisteredServiceParameters,
    RestartRegisteredServiceProposal,
)
from faultwarden.services.remediation_audit_service import RemediationAuditService


# --- Helper Fixture / Factory ---
async def _create_test_incident(
    session: AsyncSession, *, langgraph_thread_id: str | None = None
) -> IncidentModel:
    """Helper to persist a parent IncidentModel in the test session."""
    incident = IncidentModel(
        title="Test Incident for Remediation Persistence",
        status=IncidentStatus.INVESTIGATING,
        severity=IncidentSeverity.HIGH,
        source="alertmanager",
        summary="High error rate detected on demo-service.",
        fingerprint=f"fp-{uuid4().hex[:8]}",
        service="demo-service",
        alert_status="firing",
        alert_payload={},
        evidence=[],
        hypotheses=[],
        root_cause=None,
        proposed_remediations=[],
        resolution=None,
        classification=None,
        iteration_count=1,
        langgraph_thread_id=langgraph_thread_id,
    )
    session.add(incident)
    await session.flush()
    await session.refresh(incident)
    return incident


# --- Unit Tests ---
@pytest.mark.asyncio
async def test_create_proposal_persists_all_fields_and_json_roundtrip(
    db_session: AsyncSession,
) -> None:
    """1. create_proposal persists all fields including parameters/supporting_evidence_ids JSON round-trip."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset demo service fault injection",
        description="Clear simulated error mode on demo-service",
        expected_effect="5xx error rate drops to 0",
        supporting_evidence_ids=["ev-latency-1", "ev-5xx-2"],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )

    model = await service.create_proposal(proposal)

    assert model.id == UUID(proposal.id)
    assert model.incident_id == incident.id
    assert model.action_type == ActionType.RESET_DEMO_FAILURE
    assert model.title == "Reset demo service fault injection"
    assert model.description == "Clear simulated error mode on demo-service"
    assert model.expected_effect == "5xx error rate drops to 0"
    assert model.supporting_evidence_ids == ["ev-latency-1", "ev-5xx-2"]
    assert model.proposed_risk == 1
    assert model.requires_approval is False
    assert model.parameters == {"service": "demo-service"}
    assert model.created_at is not None
    assert model.updated_at is not None
    assert "Reset demo service fault injection" in repr(model)

    fetched = await service.get_proposal(model.id)
    assert fetched is not None
    assert fetched.id == model.id
    assert fetched.parameters == {"service": "demo-service"}
    assert fetched.supporting_evidence_ids == ["ev-latency-1", "ev-5xx-2"]


@pytest.mark.asyncio
async def test_create_action_decision_allowed_action(db_session: AsyncSession) -> None:
    """2. create_action_decision for an AllowedAction -> decision=ALLOWED, status=APPROVED, policy metadata populated."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset Demo Error Mode",
        description="Reset failure mode immediately",
        expected_effect="Recovery",
        supporting_evidence_ids=["ev-1"],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await service.create_proposal(proposal)

    policy_result = evaluate_policy(
        proposal, settings=RemediationSettings(enabled=True, auto_execute_max_safety_level=1)
    )
    assert isinstance(policy_result, AllowedAction)

    action_model = await service.create_action_decision(policy_result)

    assert action_model.id == UUID(policy_result.action.id)
    assert action_model.proposal_id == UUID(proposal.id)
    assert action_model.incident_id == incident.id
    assert action_model.decision == PolicyDecisionType.ALLOWED
    assert action_model.action_type == ActionType.RESET_DEMO_FAILURE
    assert action_model.status == RemediationStatus.APPROVED
    assert action_model.policy_level == 1
    assert action_model.approval_required is False
    assert action_model.executor == "demo_service.reset_failure_mode"
    assert action_model.validated_parameters == {"service": "demo-service"}
    assert action_model.reason is None
    assert action_model.approved_by is None
    assert action_model.approved_at is None
    assert "ALLOWED" in repr(action_model)


@pytest.mark.asyncio
async def test_create_action_decision_approval_required_action(db_session: AsyncSession) -> None:
    """3. create_action_decision for an ApprovalRequiredAction -> status=AWAITING_APPROVAL."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Restart demo-service",
        description="Trigger service restart",
        expected_effect="Recover healthy state",
        supporting_evidence_ids=["ev-restart"],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )
    await service.create_proposal(proposal)

    policy_result = evaluate_policy(
        proposal, settings=RemediationSettings(enabled=True, auto_execute_max_safety_level=1)
    )
    assert isinstance(policy_result, ApprovalRequiredAction)

    action_model = await service.create_action_decision(policy_result)

    assert action_model.id == UUID(policy_result.action.id)
    assert action_model.proposal_id == UUID(proposal.id)
    assert action_model.incident_id == incident.id
    assert action_model.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert action_model.action_type == ActionType.RESTART_REGISTERED_SERVICE
    assert action_model.status == RemediationStatus.AWAITING_APPROVAL
    assert action_model.policy_level == 2
    assert action_model.approval_required is True
    assert action_model.executor == "registered_service.restart_simulated"
    assert action_model.validated_parameters == {"service_id": "demo-service"}
    assert action_model.reason is not None
    assert "exceeds auto-execute threshold" in action_model.reason


@pytest.mark.asyncio
async def test_create_action_decision_rejected_action(db_session: AsyncSession) -> None:
    """4. create_action_decision for a RejectedAction -> status=REJECTED, policy metadata None, reason populated."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset Demo Error Mode (Disabled)",
        description="Reset failure mode when disabled",
        expected_effect="Recovery",
        supporting_evidence_ids=["ev-disabled"],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await service.create_proposal(proposal)

    # Disabled pipeline rejects the proposal
    policy_result = evaluate_policy(proposal, settings=RemediationSettings(enabled=False))
    assert isinstance(policy_result, RejectedAction)

    action_model = await service.create_action_decision(policy_result)

    assert action_model.proposal_id == UUID(proposal.id)
    assert action_model.incident_id == incident.id
    assert action_model.decision == PolicyDecisionType.REJECTED
    assert action_model.action_type == ActionType.RESET_DEMO_FAILURE
    assert action_model.status == RemediationStatus.REJECTED
    assert action_model.policy_level is None
    assert action_model.approval_required is None
    assert action_model.executor is None
    assert action_model.validated_parameters is None
    assert action_model.reason == "remediation pipeline disabled"


@pytest.mark.asyncio
async def test_record_approval_decision_approved_true(db_session: AsyncSession) -> None:
    """5. record_approval_decision(approved=True) -> transitions from AWAITING_APPROVAL to APPROVED, approved_by/approved_at set."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Restart service requiring approval",
        description="Restarting",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )
    await service.create_proposal(proposal)

    policy_result = evaluate_policy(proposal, settings=RemediationSettings())
    assert isinstance(policy_result, ApprovalRequiredAction)
    action_model = await service.create_action_decision(policy_result)
    assert action_model.status == RemediationStatus.AWAITING_APPROVAL

    approved_action = await service.record_approval_decision(
        action_model.id, approved=True, approved_by="sre-operator-alice"
    )

    assert approved_action.status == RemediationStatus.APPROVED
    assert approved_action.approved_by == "sre-operator-alice"
    assert approved_action.approved_at is not None

    # Refetch to ensure persistence
    refetched = await service.get_action(action_model.id)
    assert refetched is not None
    assert refetched.status == RemediationStatus.APPROVED
    assert refetched.approved_by == "sre-operator-alice"


@pytest.mark.asyncio
async def test_record_approval_decision_approved_false(db_session: AsyncSession) -> None:
    """6. record_approval_decision(approved=False) -> transitions to REJECTED."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Restart service rejected by operator",
        description="Restarting",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )
    await service.create_proposal(proposal)

    policy_result = evaluate_policy(proposal, settings=RemediationSettings())
    action_model = await service.create_action_decision(policy_result)
    assert action_model.status == RemediationStatus.AWAITING_APPROVAL

    rejected_action = await service.record_approval_decision(
        action_model.id, approved=False, approved_by="sre-operator-bob"
    )

    assert rejected_action.status == RemediationStatus.REJECTED
    assert rejected_action.approved_by == "sre-operator-bob"
    assert rejected_action.approved_at is not None


@pytest.mark.asyncio
async def test_record_approval_decision_nonexistent_action_raises(
    db_session: AsyncSession,
) -> None:
    """7. record_approval_decision on a nonexistent action_id raises RemediationActionNotFoundError."""
    service = RemediationAuditService(session=db_session)
    fake_id = uuid4()

    with pytest.raises(RemediationActionNotFoundError) as exc_info:
        await service.record_approval_decision(fake_id, approved=True, approved_by="admin")

    assert str(fake_id) in str(exc_info.value)
    assert exc_info.value.action_id == str(fake_id)


@pytest.mark.asyncio
async def test_record_execution_result_persists_and_links(db_session: AsyncSession) -> None:
    """8. record_execution_result persists a RemediationResult correctly and links to action_id."""
    service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset demo error mode",
        description="Reset",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await service.create_proposal(proposal)

    policy_result = evaluate_policy(proposal, settings=RemediationSettings())
    action_model = await service.create_action_decision(policy_result)

    started_at = datetime.now(UTC)
    completed_at = datetime.now(UTC)
    result_schema = RemediationResult(
        action_id=str(action_model.id),
        status=RemediationExecutionStatus.SUCCEEDED,
        started_at=started_at,
        completed_at=completed_at,
        success=True,
        summary="Successfully cleared simulated error mode on demo-service.",
        error=None,
        before_state={"error_mode": True, "http_status": 500},
        after_state={"error_mode": False, "http_status": 200},
    )

    result_model = await service.record_execution_result(result_schema)

    assert result_model.id is not None
    assert result_model.action_id == action_model.id
    assert result_model.status == RemediationExecutionStatus.SUCCEEDED
    assert result_model.success is True
    assert result_model.summary == "Successfully cleared simulated error mode on demo-service."
    assert result_model.error is None
    assert result_model.before_state == {"error_mode": True, "http_status": 500}
    assert result_model.after_state == {"error_mode": False, "http_status": 200}
    assert "SUCCEEDED" in repr(result_model)


@pytest.mark.asyncio
async def test_list_actions_for_incident_ordering_and_scoping(db_session: AsyncSession) -> None:
    """9. list_actions_for_incident returns only that incident's actions, ordered most recent first."""
    service = RemediationAuditService(session=db_session)

    incident_1 = await _create_test_incident(db_session)
    incident_2 = await _create_test_incident(db_session)

    # Create 2 proposals and actions for incident 1
    p1 = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident_1.id),
        title="Action 1",
        description="First",
        expected_effect="None",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await service.create_proposal(p1)
    res1 = evaluate_policy(p1, settings=RemediationSettings())
    a1 = await service.create_action_decision(res1)
    a1.created_at = datetime(2026, 8, 16, 10, 0, 0, tzinfo=UTC)
    await db_session.flush()

    p2 = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id=str(incident_1.id),
        title="Action 2",
        description="Second",
        expected_effect="None",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )
    await service.create_proposal(p2)
    res2 = evaluate_policy(p2, settings=RemediationSettings())
    a2 = await service.create_action_decision(res2)
    a2.created_at = datetime(2026, 8, 16, 10, 5, 0, tzinfo=UTC)
    await db_session.flush()

    # Create 1 proposal and action for incident 2
    p3 = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident_2.id),
        title="Action for incident 2",
        description="Third",
        expected_effect="None",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await service.create_proposal(p3)
    res3 = evaluate_policy(p3, settings=RemediationSettings())
    a3 = await service.create_action_decision(res3)

    # Query actions for incident 1
    actions_1 = await service.list_actions_for_incident(incident_1.id)
    assert len(actions_1) == 2
    assert {a.id for a in actions_1} == {a1.id, a2.id}
    # Most recent first
    assert actions_1[0].id == a2.id
    assert actions_1[1].id == a1.id

    # Query actions for incident 2
    actions_2 = await service.list_actions_for_incident(incident_2.id)
    assert len(actions_2) == 1
    assert actions_2[0].id == a3.id


@pytest.mark.asyncio
async def test_sqlite_foreign_key_enforcement_with_pragma(db_session: AsyncSession) -> None:
    """10. FK integrity: creating a RemediationActionModel for a nonexistent proposal_id fails when FKs are ON."""
    # SQLite requires PRAGMA foreign_keys=ON to enforce foreign key constraints
    await db_session.execute(text("PRAGMA foreign_keys=ON"))

    incident = await _create_test_incident(db_session)
    nonexistent_proposal_id = uuid4()

    invalid_action = RemediationActionModel(
        id=uuid4(),
        proposal_id=nonexistent_proposal_id,
        incident_id=incident.id,
        decision=PolicyDecisionType.ALLOWED,
        action_type=ActionType.RESET_DEMO_FAILURE,
        policy_level=1,
        approval_required=False,
        executor="demo_service.reset_failure_mode",
        validated_parameters={"service": "demo-service"},
        reason=None,
        status=RemediationStatus.APPROVED,
    )
    db_session.add(invalid_action)

    with pytest.raises(IntegrityError):
        await db_session.flush()

    await db_session.rollback()


@pytest.mark.asyncio
async def test_incident_langgraph_thread_id_persistence(db_session: AsyncSession) -> None:
    """Verify that IncidentModel correctly persists the langgraph_thread_id column."""
    thread_id = "thread_investigation_run_42"
    incident = await _create_test_incident(db_session, langgraph_thread_id=thread_id)

    assert incident.langgraph_thread_id == thread_id

    fetched = await db_session.get(IncidentModel, incident.id)
    assert fetched is not None
    assert fetched.langgraph_thread_id == "thread_investigation_run_42"


@pytest.mark.asyncio
async def test_create_action_decision_nonexistent_proposal_raises(
    db_session: AsyncSession,
) -> None:
    """11. create_action_decision with a nonexistent proposal_id raises RemediationProposalNotFoundError and rolls back/inserts nothing."""
    service = RemediationAuditService(session=db_session)
    nonexistent_proposal_id = str(uuid4())

    # Direct AllowedAction with a proposal_id that was never created
    allowed_action = AllowedAction(
        action=ResetDemoFailureExecutableAction(
            id=str(uuid4()),
            proposal_id=nonexistent_proposal_id,
            policy_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
            approval_required=False,
            executor="demo_service.reset_failure_mode",
            validated_parameters=ResetDemoFailureParameters(service="demo-service"),
        )
    )

    count_stmt = select(func.count()).select_from(RemediationActionModel)
    initial_count = (await db_session.execute(count_stmt)).scalar_one()

    with pytest.raises(RemediationProposalNotFoundError) as exc_info_allowed:
        await service.create_action_decision(allowed_action)

    assert exc_info_allowed.value.proposal_id == nonexistent_proposal_id
    assert nonexistent_proposal_id in str(exc_info_allowed.value)

    # Ensure no row was inserted
    count_after_allowed = (await db_session.execute(count_stmt)).scalar_one()
    assert count_after_allowed == initial_count

    # Direct RejectedAction with a proposal_id that was never created
    rejected_proposal_id = str(uuid4())
    rejected_action = RejectedAction(
        proposal_id=rejected_proposal_id,
        action_type=ActionType.RESET_DEMO_FAILURE,
        reason="remediation pipeline disabled",
    )

    with pytest.raises(RemediationProposalNotFoundError) as exc_info_rejected:
        await service.create_action_decision(rejected_action)

    assert exc_info_rejected.value.proposal_id == rejected_proposal_id
    assert rejected_proposal_id in str(exc_info_rejected.value)

    # Ensure no row was inserted
    count_after_rejected = (await db_session.execute(count_stmt)).scalar_one()
    assert count_after_rejected == initial_count
