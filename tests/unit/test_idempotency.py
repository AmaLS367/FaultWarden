"""Unit tests for side-effect idempotency and execution claim safety (Issue 6).

Invariants:
- RemediationActionModel stores idempotency_key.
- RemediationAuditService.claim_action_for_execution atomically claims action (APPROVED -> EXECUTING).
- Duplicate claim on non-approved action raises RemediationExecutionClaimError.
- DemoServiceExecutor propagates X-Idempotency-Key header on remediation POST requests.
- demo-service deduplicates requests with identical X-Idempotency-Key.
"""

from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from demo_service.app.main import app as demo_app
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.config import RemediationSettings
from faultwarden.core.exceptions import RemediationExecutionClaimError
from faultwarden.core.policy import evaluate_policy
from faultwarden.db.models.incident import IncidentModel
from faultwarden.integrations.executors.demo_service import DemoServiceExecutor
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import (
    AllowedAction,
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
)
from faultwarden.services.remediation_audit_service import RemediationAuditService


async def _create_test_incident(db_session: AsyncSession) -> IncidentModel:
    incident = IncidentModel(
        id=uuid4(),
        title="[CRITICAL] Idempotency Test Incident",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint=f"fp-idempotency-{uuid4()}",
        service="demo-service",
        alert_payload={},
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(incident)
    return incident


@pytest.mark.asyncio
async def test_action_decision_stores_deterministic_idempotency_key(
    db_session: AsyncSession,
) -> None:
    """RemediationActionModel is persisted with a deterministic idempotency_key."""
    audit_service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset Demo Fault",
        description="Reset",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await audit_service.create_proposal(proposal)

    policy_result = evaluate_policy(proposal, settings=RemediationSettings())
    assert isinstance(policy_result, AllowedAction)

    action_model = await audit_service.create_action_decision(policy_result)

    assert action_model.idempotency_key is not None
    assert action_model.idempotency_key.startswith("rem-exec-")


@pytest.mark.asyncio
async def test_claim_action_for_execution_transitions_to_executing(
    db_session: AsyncSession,
) -> None:
    """claim_action_for_execution transitions action from APPROVED to EXECUTING with lease."""
    audit_service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset Demo Fault",
        description="Reset",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await audit_service.create_proposal(proposal)
    policy_result = evaluate_policy(proposal, settings=RemediationSettings())
    action_model = await audit_service.create_action_decision(policy_result)

    claimed_action = await audit_service.claim_action_for_execution(
        action_model.id, lease_seconds=60
    )

    assert claimed_action.status.value == "EXECUTING"
    assert claimed_action.claim_expires_at is not None


@pytest.mark.asyncio
async def test_duplicate_claim_on_already_executing_action_raises(
    db_session: AsyncSession,
) -> None:
    """Attempting to claim an already EXECUTING action raises RemediationExecutionClaimError."""
    audit_service = RemediationAuditService(session=db_session)
    incident = await _create_test_incident(db_session)

    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(incident.id),
        title="Reset Demo Fault",
        description="Reset",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    await audit_service.create_proposal(proposal)
    policy_result = evaluate_policy(proposal, settings=RemediationSettings())
    action_model = await audit_service.create_action_decision(policy_result)

    # First claim succeeds
    await audit_service.claim_action_for_execution(action_model.id, lease_seconds=60)

    # Second claim must fail
    with pytest.raises(RemediationExecutionClaimError) as exc_info:
        await audit_service.claim_action_for_execution(action_model.id, lease_seconds=60)

    assert exc_info.value.action_id == str(action_model.id)
    assert "already EXECUTING" in exc_info.value.reason


@pytest.mark.asyncio
async def test_demo_service_executor_propagates_idempotency_key_header() -> None:
    """DemoServiceExecutor includes X-Idempotency-Key header on outbound HTTP requests."""
    executor = DemoServiceExecutor(
        settings=RemediationSettings(demo_service_url="http://localhost:8001")
    )
    action = ResetDemoFailureExecutableAction(
        id=str(uuid4()),
        proposal_id=str(uuid4()),
        policy_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        approval_required=False,
        executor="demo_service.reset_failure_mode",
        validated_parameters=ResetDemoFailureParameters(service="demo-service"),
        idempotency_key="idempotency-key-test-12345",
    )

    captured_headers: dict[str, str] = {}

    async def mock_get(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(200, json={"error_mode": True})

    async def mock_post(url: str, **kwargs: object) -> httpx.Response:
        headers = kwargs.get("headers")
        if isinstance(headers, dict):
            captured_headers.update(headers)
        return httpx.Response(
            200, json={"error_mode": False, "status": "ok", "message": "Fault injection disabled"}
        )

    with (
        patch.object(httpx.AsyncClient, "get", side_effect=mock_get),
        patch.object(httpx.AsyncClient, "post", side_effect=mock_post),
    ):
        res = await executor.reset_failure_mode(action)

    assert res.success is True
    assert captured_headers.get("X-Idempotency-Key") == "idempotency-key-test-12345"


@pytest.mark.asyncio
async def test_demo_service_app_deduplicates_by_idempotency_key() -> None:
    """demo-service endpoint /debug/error-mode/{enabled} deduplicates identical idempotency keys."""
    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        key = f"idem-key-{uuid4()}"

        # First request
        resp1 = await client.post(
            "/debug/error-mode/false",
            headers={"X-Idempotency-Key": key},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()

        # Second duplicate request
        resp2 = await client.post(
            "/debug/error-mode/false",
            headers={"X-Idempotency-Key": key},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()

        assert data1 == data2
        assert resp2.headers.get("X-Cache") == "HIT"
