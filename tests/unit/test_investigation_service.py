"""Unit tests for InvestigationService execution, persistence, and endpoints."""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.exceptions import RemediationNotAwaitingApprovalError
from faultwarden.db.models.remediation import RemediationResultModel
from faultwarden.graph.builder import build_incident_graph
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.hypothesis import (
    Hypothesis,
    HypothesisStatus,
)
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)
from faultwarden.schemas.remediation import (
    ActionType,
    ApprovalDecision,
    PolicyDecisionType,
    RemediationAction,
    RemediationExecutionStatus,
    RemediationResult,
    RemediationSafetyLevel,
    RemediationStatus,
)
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService
from faultwarden.services.remediation_audit_service import RemediationAuditService


@pytest.mark.asyncio
async def test_investigation_service_execution_and_persistence(
    db_session: AsyncSession,
) -> None:
    """Test running an autonomous investigation on an incident and verifying DB persistence."""
    incident_service = IncidentService(session=db_session)
    investigation_service = InvestigationService(incident_service=incident_service)

    # 1. Create a raw incident from alert payload
    create_dto = IncidentCreate(
        title="[CRITICAL] DemoServiceHighErrorRate in demo-service",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        summary="5xx error rate alert firing",
        fingerprint="fp-test-investigation-01",
        service="demo-service",
        alert_status="firing",
        alert_payload={
            "commonLabels": {
                "alertname": "DemoServiceHighErrorRate",
                "service": "demo-service",
                "severity": "critical",
            },
            "commonAnnotations": {
                "summary": "Elevated 5xx error rate in demo-service",
                "description": "Database connection pool exhausted in demo-service checkout endpoint",
            },
        },
    )
    incident = await incident_service.create_incident(create_dto)
    assert incident.status == IncidentStatus.DETECTED
    assert len(incident.evidence or []) == 0

    # 2. Run investigation
    updated_incident = await investigation_service.run_investigation(incident.id)

    # 3. Verify resulting incident state and persistence
    assert updated_incident.id == incident.id
    assert updated_incident.status in (
        IncidentStatus.ROOT_CAUSE_IDENTIFIED,
        IncidentStatus.REMEDIATION_PROPOSED,
        IncidentStatus.AWAITING_APPROVAL,
    )
    assert len(updated_incident.evidence) >= 1
    assert len(updated_incident.hypotheses) >= 1
    assert updated_incident.root_cause is not None
    assert updated_incident.root_cause["confidence"] >= 0.75
    assert len(updated_incident.proposed_remediations) >= 1

    # Verify reload from database confirms persistence
    reloaded = await incident_service.get_incident(incident.id)
    assert len(reloaded.evidence) == len(updated_incident.evidence)
    assert reloaded.root_cause is not None
    assert (
        reloaded.root_cause["primary_hypothesis_id"]
        == updated_incident.root_cause["primary_hypothesis_id"]
    )


@pytest.mark.asyncio
async def test_investigation_api_endpoints(
    client: AsyncClient,
    sample_alertmanager_payload: dict[str, Any],
) -> None:
    """Test GET /incidents/{id}/investigation and POST /incidents/{id}/investigate API endpoints."""
    # 1. Create incident via webhook
    post_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json=sample_alertmanager_payload,
    )
    assert post_resp.status_code == 201
    incident_id = post_resp.json()["incident_id"]

    # 2. Fetch initial investigation details
    get_inv_resp = await client.get(f"/api/v1/incidents/{incident_id}/investigation")
    assert get_inv_resp.status_code == 200
    inv_data = get_inv_resp.json()
    assert inv_data["incident_id"] == incident_id

    # 3. Explicitly trigger/re-run investigation via POST endpoint
    run_inv_resp = await client.post(f"/api/v1/incidents/{incident_id}/investigate")
    assert run_inv_resp.status_code == 200
    run_data = run_inv_resp.json()
    assert run_data["incident_id"] == incident_id
    assert run_data["status"] in (
        IncidentStatus.ROOT_CAUSE_IDENTIFIED.value,
        IncidentStatus.REMEDIATION_PROPOSED.value,
        IncidentStatus.AWAITING_APPROVAL.value,
    )
    assert len(run_data["evidence"]) >= 1
    assert len(run_data["hypotheses"]) >= 1
    assert run_data["root_cause"] is not None
    assert len(run_data["remediation_proposals"]) >= 1
    assert run_data["classification"] is not None
    assert run_data["iteration_count"] >= 1
    assert run_data["selected_hypothesis"] is not None
    assert run_data["selected_hypothesis"]["id"] == run_data["root_cause"]["primary_hypothesis_id"]

    # 3b. GET after the run must reflect the same persisted investigation metadata
    get_after_run_resp = await client.get(f"/api/v1/incidents/{incident_id}/investigation")
    assert get_after_run_resp.status_code == 200
    after_run_data = get_after_run_resp.json()
    assert after_run_data["classification"] is not None
    assert after_run_data["iteration_count"] >= 1
    assert after_run_data["selected_hypothesis"] is not None

    # 4. Verify 404 for non-existent incident investigation
    fake_id = str(uuid4())
    fake_get = await client.get(f"/api/v1/incidents/{fake_id}/investigation")
    assert fake_get.status_code == 404


@pytest.mark.asyncio
async def test_weak_hypothesis_triggers_bounded_iteration_loop() -> None:
    """Test that low-confidence hypothesis causes follow-up telemetry loop bounded by MAX_INVESTIGATION_ITERATIONS."""
    graph = build_incident_graph()

    # Create a state starting with a low-confidence hypothesis
    initial_state: IncidentInvestigationState = {
        "incident_id": "inc-loop-test",
        "incident_context": {"service": "demo-service"},
        "alert": {
            "commonLabels": {"alertname": "TransientAnomaly", "service": "demo-service"},
            "commonAnnotations": {"summary": "Brief 5xx spike observed"},
        },
        "classification": None,
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [
            Hypothesis(
                id=str(uuid4()),
                title="Unknown Intermittent Glitch",
                description="Insufficient telemetry to confirm",
                affected_component="demo-service",
                confidence_score=0.40,
                status=HypothesisStatus.PROPOSED,
                supporting_evidence_ids=[],
                missing_evidence_needed=["sum(rate(http_requests_total[1m]))"],
            )
        ],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [],
        "iteration_count": 1,
        "missing_evidence_queries": ["sum(rate(http_requests_total[1m]))"],
        "investigation_status": "INVESTIGATING",
        "summary": "",
        "errors": [],
    }

    final_state = await graph.ainvoke(initial_state)

    # Workflow must terminate within max iterations and propose safe remediations
    assert final_state["iteration_count"] >= 1
    assert "__interrupt__" in final_state or final_state["investigation_status"] in (
        "COMPLETED",
        "INCONCLUSIVE",
    )
    assert len(final_state["remediation_proposals"]) >= 1
    assert final_state["remediation_proposals"][0].proposed_risk in (
        RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
    )


@pytest.mark.asyncio
async def test_investigation_inconclusive_selected_hypothesis_endpoint(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """GET /incidents/{id}/investigation should populate selected_hypothesis even when inconclusive."""
    incident_service = IncidentService(session=db_session)
    create_dto = IncidentCreate(
        title="[WARNING] Intermittent spike",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.MEDIUM,
        source="alertmanager",
        summary="Brief intermittent alert",
        fingerprint="fp-test-inconclusive-01",
        service="demo-service",
        alert_status="firing",
        alert_payload={},
    )
    incident = await incident_service.create_incident(create_dto)

    # Persist an investigation result that ended in INCONCLUSIVE status
    inconclusive_hyp = Hypothesis(
        id="hyp-inconclusive-1",
        title="Potential Network Flap",
        description="Network jitter between microservices",
        affected_component="demo-service",
        confidence_score=0.65,
        status=HypothesisStatus.INCONCLUSIVE,
        supporting_evidence_ids=[],
    )

    update_dto = IncidentUpdate(
        status=IncidentStatus.REMEDIATION_PROPOSED,
        hypotheses=[inconclusive_hyp],
        root_cause=None,
        summary="Leading hypothesis: Potential Network Flap",
    )
    await incident_service.update_incident(incident.id, update_dto)

    resp = await client.get(f"/api/v1/incidents/{incident.id}/investigation")
    assert resp.status_code == 200
    data = resp.json()
    assert data["selected_hypothesis"] is not None
    assert data["selected_hypothesis"]["id"] == "hyp-inconclusive-1"
    assert data["selected_hypothesis"]["title"] == "Potential Network Flap"
    assert data["root_cause"] is None


@pytest.mark.asyncio
async def test_investigation_service_level_2_pause_and_persistence(
    db_session: AsyncSession,
) -> None:
    """Test 6: run_investigation on Level-2 scenario persists proposal + AWAITING_APPROVAL action and pauses."""
    incident_service = IncidentService(session=db_session)
    mock_executor = AsyncMock()
    investigation_service = InvestigationService(
        incident_service=incident_service,
        remediation_executor=mock_executor,
    )

    create_dto = IncidentCreate(
        title="[CRITICAL] High Latency in demo-service",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        summary="Service degradation alert",
        fingerprint="fp-test-level2-pause",
        service="demo-service",
        alert_status="firing",
        alert_payload={},
    )
    incident = await incident_service.create_incident(create_dto)

    updated_incident = await investigation_service.run_investigation(incident.id)

    # 1. Assert status is AWAITING_APPROVAL and langgraph_thread_id is persisted
    assert updated_incident.status == IncidentStatus.AWAITING_APPROVAL
    assert updated_incident.langgraph_thread_id is not None

    # 2. Assert RemediationAuditService has persisted proposal and action in AWAITING_APPROVAL
    audit_service = RemediationAuditService(session=db_session)
    actions = await audit_service.list_actions_for_incident(incident.id)
    assert len(actions) == 1
    assert actions[0].status == RemediationStatus.AWAITING_APPROVAL
    assert actions[0].decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert actions[0].action_type == ActionType.RESTART_REGISTERED_SERVICE

    proposal = await audit_service.get_proposal(actions[0].proposal_id)
    assert proposal is not None
    assert proposal.incident_id == incident.id
    mock_executor.assert_not_called()


@pytest.mark.asyncio
async def test_investigation_service_resume_approval(
    db_session: AsyncSession,
) -> None:
    """Test 7: resume_remediation_approval with APPROVE executes action and records audit results."""
    incident_service = IncidentService(session=db_session)
    mock_executor = AsyncMock()

    async def _fake_executor(action: RemediationAction) -> RemediationResult:
        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            success=True,
            summary="Restart succeeded",
        )

    mock_executor.side_effect = _fake_executor

    investigation_service = InvestigationService(
        incident_service=incident_service,
        remediation_executor=mock_executor,
        remediation_validator=AsyncMock(return_value=True),
    )

    create_dto = IncidentCreate(
        title="[CRITICAL] Error spike in demo-service",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint="fp-test-resume-approve",
        service="demo-service",
        alert_status="firing",
        alert_payload={},
    )
    incident = await incident_service.create_incident(create_dto)
    await investigation_service.run_investigation(incident.id)

    # Resume with APPROVE
    resumed_incident = await investigation_service.resume_remediation_approval(
        incident.id,
        decision=ApprovalDecision.APPROVE,
        approved_by="admin@faultwarden.io",
    )

    # With a validator confirming recovery, a successfully executed and validated remediation
    # resolves the incident (see InvestigationService._decide_terminal_status).
    assert resumed_incident.status == IncidentStatus.RESOLVED
    assert resumed_incident.resolution is not None
    mock_executor.assert_awaited_once()

    audit_service = RemediationAuditService(session=db_session)
    actions = await audit_service.list_actions_for_incident(incident.id)
    assert len(actions) == 1
    assert actions[0].status == RemediationStatus.APPROVED
    assert actions[0].approved_by == "admin@faultwarden.io"
    assert actions[0].approved_at is not None

    # Check execution result row in DB
    stmt = select(RemediationResultModel).where(RemediationResultModel.action_id == actions[0].id)
    res = await db_session.execute(stmt)
    result_model = res.scalar_one_or_none()
    assert result_model is not None
    assert result_model.success is True
    assert result_model.status == RemediationExecutionStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_investigation_service_resume_not_awaiting_approval_error(
    db_session: AsyncSession,
) -> None:
    """Test 8: resume_remediation_approval on non-awaiting incident raises RemediationNotAwaitingApprovalError."""
    incident_service = IncidentService(session=db_session)
    mock_executor = AsyncMock()
    investigation_service = InvestigationService(
        incident_service=incident_service,
        remediation_executor=mock_executor,
    )

    create_dto = IncidentCreate(
        title="[INFO] Normal Incident",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.LOW,
        source="alertmanager",
        fingerprint="fp-test-not-awaiting",
        service="demo-service",
    )
    incident = await incident_service.create_incident(create_dto)

    with pytest.raises(RemediationNotAwaitingApprovalError):
        await investigation_service.resume_remediation_approval(
            incident.id,
            decision=ApprovalDecision.APPROVE,
            approved_by="operator@faultwarden.io",
        )

    mock_executor.assert_not_called()


@pytest.mark.asyncio
async def test_investigation_service_duplicate_resume_fails(
    db_session: AsyncSession,
) -> None:
    """Test 9: Two rapid resume calls on same incident fail on the second call without duplicate execution."""
    incident_service = IncidentService(session=db_session)
    mock_executor = AsyncMock()

    async def _fake_executor(action: RemediationAction) -> RemediationResult:
        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            success=True,
            summary="Restart succeeded",
        )

    mock_executor.side_effect = _fake_executor

    investigation_service = InvestigationService(
        incident_service=incident_service,
        remediation_executor=mock_executor,
        remediation_validator=AsyncMock(return_value=True),
    )

    create_dto = IncidentCreate(
        title="[CRITICAL] Demo incident for double resume",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint="fp-test-double-resume",
        service="demo-service",
    )
    incident = await incident_service.create_incident(create_dto)
    await investigation_service.run_investigation(incident.id)

    # First resume succeeds
    resumed_1 = await investigation_service.resume_remediation_approval(
        incident.id,
        decision=ApprovalDecision.APPROVE,
        approved_by="operator-1@faultwarden.io",
    )
    assert resumed_1.status != IncidentStatus.AWAITING_APPROVAL

    # Second resume call fails
    with pytest.raises(RemediationNotAwaitingApprovalError):
        await investigation_service.resume_remediation_approval(
            incident.id,
            decision=ApprovalDecision.APPROVE,
            approved_by="operator-2@faultwarden.io",
        )

    assert mock_executor.await_count == 1
