"""Integration tests for the remediation approval/rejection API (FaultWarden v0.3, Phase 8)."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.api.dependencies import get_investigation_service
from faultwarden.main import app
from faultwarden.schemas.incident import IncidentCreate, IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import RemediationAction, RemediationResult, RemediationStatus
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService
from faultwarden.services.remediation_audit_service import RemediationAuditService


def _fake_success_executor() -> AsyncMock:
    """Build a mock executor that reports a successful execution, matching existing test convention."""
    mock_executor = AsyncMock()

    async def _fake(action: RemediationAction) -> RemediationResult:
        return RemediationResult(
            action_id=action.id,
            status="SUCCEEDED",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            success=True,
            summary="Restart succeeded",
        )

    mock_executor.side_effect = _fake
    return mock_executor


async def _create_awaiting_approval_incident(db_session: AsyncSession, fingerprint: str) -> UUID:
    """Create an incident and run it to AWAITING_APPROVAL via direct service calls (no HTTP round-trip needed for setup)."""
    incident_service = IncidentService(session=db_session)
    investigation_service = InvestigationService(
        incident_service=incident_service, remediation_executor=AsyncMock()
    )
    create_dto = IncidentCreate(
        title="[CRITICAL] API test incident",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint=fingerprint,
        service="demo-service",
        alert_status="firing",
        alert_payload={},
    )
    incident = await incident_service.create_incident(create_dto)
    updated = await investigation_service.run_investigation(incident.id)
    assert updated.status == IncidentStatus.AWAITING_APPROVAL
    return UUID(str(incident.id))


async def _get_awaiting_action_id(db_session: AsyncSession, incident_id: UUID) -> UUID:
    audit_service = RemediationAuditService(session=db_session)
    actions = await audit_service.list_actions_for_incident(incident_id)
    awaiting = [a for a in actions if a.status == RemediationStatus.AWAITING_APPROVAL]
    assert len(awaiting) == 1
    return UUID(str(awaiting[0].id))


class _OverrideInvestigationServiceCtx:
    """Context manager overriding get_investigation_service with a mock-executor-backed instance for one test."""

    def __init__(self, db_session: AsyncSession, executor: AsyncMock) -> None:
        self._db_session = db_session
        self._executor = executor

    async def __aenter__(self) -> None:
        def _override() -> InvestigationService:
            return InvestigationService(
                incident_service=IncidentService(session=self._db_session),
                remediation_executor=self._executor,
            )

        app.dependency_overrides[get_investigation_service] = _override

    async def __aexit__(self, *exc_info: object) -> None:
        app.dependency_overrides.pop(get_investigation_service, None)


@pytest.mark.asyncio
async def test_list_remediations_shows_awaiting_approval_action(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """1. GET list on a paused incident returns one AWAITING_APPROVAL action."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-list-1")

    resp = await client.get(f"/api/v1/incidents/{incident_id}/remediations")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["status"] == "AWAITING_APPROVAL"
    assert body[0]["decision"] == "APPROVAL_REQUIRED"


@pytest.mark.asyncio
async def test_get_single_remediation_no_result_yet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """2. GET single remediation returns the action with result absent before execution."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-get-1")
    action_id = await _get_awaiting_action_id(db_session, incident_id)

    resp = await client.get(f"/api/v1/incidents/{incident_id}/remediations/{action_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(action_id)
    assert body["result"] is None


@pytest.mark.asyncio
async def test_get_remediation_wrong_incident_returns_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """3. GET a remediation_id that exists but belongs to a different incident returns 404."""
    incident_id_1 = await _create_awaiting_approval_incident(db_session, "fp-api-wrong-inc-1")
    incident_id_2 = await _create_awaiting_approval_incident(db_session, "fp-api-wrong-inc-2")
    action_id_1 = await _get_awaiting_action_id(db_session, incident_id_1)

    resp = await client.get(f"/api/v1/incidents/{incident_id_2}/remediations/{action_id_1}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_remediation_nonexistent_returns_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """4. GET a remediation_id that doesn't exist at all returns 404."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-nonexistent-1")
    resp = await client.get(f"/api/v1/incidents/{incident_id}/remediations/{uuid4()}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_approve_executes_and_persists_result(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """5. POST approve executes the action; a follow-up GET shows a populated successful result."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-approve-1")
    action_id = await _get_awaiting_action_id(db_session, incident_id)
    executor = _fake_success_executor()

    async with _OverrideInvestigationServiceCtx(db_session, executor):
        resp = await client.post(
            f"/api/v1/incidents/{incident_id}/remediations/{action_id}/approve",
            json={"approved_by": "operator-test"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approved_by"] == "operator-test"
    assert body["status"] != "AWAITING_APPROVAL"
    executor.assert_awaited_once()

    follow_up = await client.get(f"/api/v1/incidents/{incident_id}/remediations/{action_id}")
    assert follow_up.status_code == 200
    follow_body = follow_up.json()
    assert follow_body["result"] is not None
    assert follow_body["result"]["success"] is True


@pytest.mark.asyncio
async def test_reject_never_executes(client: AsyncClient, db_session: AsyncSession) -> None:
    """6. POST reject never invokes the executor; no result row is created."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-reject-1")
    action_id = await _get_awaiting_action_id(db_session, incident_id)
    executor = AsyncMock()

    async with _OverrideInvestigationServiceCtx(db_session, executor):
        resp = await client.post(
            f"/api/v1/incidents/{incident_id}/remediations/{action_id}/reject",
            json={"approved_by": "operator-test"},
        )
    assert resp.status_code == 200
    executor.assert_not_called()

    audit_service = RemediationAuditService(session=db_session)
    result = await audit_service.get_result_for_action(action_id)
    assert result is None


@pytest.mark.asyncio
async def test_double_approve_second_call_returns_409_no_double_execution(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """7. Two approve calls on the same remediation_id: the second returns 409, executor runs once."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-double-1")
    action_id = await _get_awaiting_action_id(db_session, incident_id)
    executor = _fake_success_executor()

    async with _OverrideInvestigationServiceCtx(db_session, executor):
        first = await client.post(
            f"/api/v1/incidents/{incident_id}/remediations/{action_id}/approve",
            json={"approved_by": "operator-1"},
        )
        assert first.status_code == 200

        second = await client.post(
            f"/api/v1/incidents/{incident_id}/remediations/{action_id}/approve",
            json={"approved_by": "operator-2"},
        )
        assert second.status_code == 409

    assert executor.await_count == 1


@pytest.mark.asyncio
async def test_approve_nonexistent_remediation_returns_404_not_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """9. Approving a remediation_id that doesn't exist returns 404, not 409."""
    incident_id = await _create_awaiting_approval_incident(db_session, "fp-api-approve-404-1")
    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/remediations/{uuid4()}/approve",
        json={"approved_by": "operator-test"},
    )
    assert resp.status_code == 404
