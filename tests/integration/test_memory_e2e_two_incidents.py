from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.api.dependencies import (
    get_db,
    get_embedding_provider,
    get_llm_provider,
)
from faultwarden.integrations.embedding.provider import MockEmbeddingProvider
from faultwarden.integrations.llm.provider import MockLLMProvider
from faultwarden.main import create_app
from faultwarden.schemas.incident import IncidentCreate, IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import (
    RemediationAction,
    RemediationExecutionStatus,
    RemediationResult,
)
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService


@pytest.mark.asyncio
async def test_two_incident_memory_and_postmortem_e2e(
    db_session: AsyncSession,
) -> None:
    """E2E Test of the full incident memory and postmortem workflow across two successive incidents."""
    app = create_app()

    mock_llm = MockLLMProvider()
    mock_embedding = MockEmbeddingProvider(dimensions=384)

    async def _mock_executor(action: RemediationAction) -> RemediationResult:
        now = datetime.now(UTC)
        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=now,
            completed_at=now,
            success=True,
            summary=f"Successfully executed {action.action_type} for proposal {action.proposal_id}",
        )

    async def _mock_validator(_action: Any) -> bool:
        return True

    # Dependency overrides
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_llm_provider] = lambda: mock_llm
    app.dependency_overrides[get_embedding_provider] = lambda: mock_embedding

    incident_svc = IncidentService(session=db_session)
    investigation_svc = InvestigationService(
        incident_service=incident_svc,
        llm_provider=mock_llm,
        embedding_provider=mock_embedding,
        remediation_executor=_mock_executor,
        remediation_validator=_mock_validator,
    )

    # =========================================================================
    # PHASE 1: Incident A (First Incident)
    # =========================================================================
    inc_a_data = IncidentCreate(
        title="Database pool exhausted on demo-service",
        service="demo-service",
        severity=IncidentSeverity.CRITICAL,
        alert_payload={
            "groupLabels": {"alertname": "DatabasePoolExhausted", "service": "demo-service"},
            "commonLabels": {"service": "demo-service", "severity": "critical"},
            "commonAnnotations": {
                "summary": "Database connection pool exhausted on demo-service",
                "description": "Active connections reached pool limit of 10",
            },
        },
    )
    incident_a = await incident_svc.create_incident(inc_a_data)
    await db_session.commit()

    # Run investigation for Incident A
    updated_a = await investigation_svc.run_investigation(incident_a.id)

    # Verify Incident A is RESOLVED
    assert updated_a.status == IncidentStatus.RESOLVED
    assert updated_a.root_cause is not None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Check Incident A Postmortem endpoint
        pm_resp_a = await client.get(f"/api/v1/incidents/{incident_a.id}/postmortem")
        assert pm_resp_a.status_code == 200
        pm_data_a = pm_resp_a.json()
        assert pm_data_a["incident_id"] == str(incident_a.id)
        assert len(pm_data_a["timeline"]) >= 3
        assert len(pm_data_a["follow_up_actions"]) >= 1

        # Check Incident A Memory endpoint
        mem_resp_a = await client.get(f"/api/v1/incidents/{incident_a.id}/memory")
        assert mem_resp_a.status_code == 200
        mem_data_a = mem_resp_a.json()
        assert mem_data_a["incident_id"] == str(incident_a.id)
        assert mem_data_a["service"] == "demo-service"

        # Search Memory endpoint to confirm Incident A is retrievable
        search_resp = await client.post(
            "/api/v1/memory/search",
            json={
                "query": "Database connection pool exhausted on demo-service",
                "service": "demo-service",
                "limit": 5,
                "min_similarity": 0.1,
            },
        )
        assert search_resp.status_code == 200
        search_data = search_resp.json()
        assert search_data["total_found"] >= 1
        assert search_data["results"][0]["incident_id"] == str(incident_a.id)

        # =========================================================================
        # PHASE 2: Incident B (Second Incident, Historically Similar)
        # =========================================================================
        inc_b_data = IncidentCreate(
            title="Database pool exhausted on demo-service recurring",
            service="demo-service",
            severity=IncidentSeverity.CRITICAL,
            alert_payload={
                "groupLabels": {"alertname": "DatabasePoolExhausted", "service": "demo-service"},
                "commonLabels": {"service": "demo-service", "severity": "critical"},
                "commonAnnotations": {
                    "summary": "Database connection pool exhausted on demo-service",
                    "description": "Active connections reached pool limit again",
                },
            },
        )
        incident_b = await incident_svc.create_incident(inc_b_data)
        await db_session.commit()

        # Check /similar endpoint for Incident B before investigation
        sim_resp_b = await client.get(
            f"/api/v1/incidents/{incident_b.id}/similar?min_similarity=0.1"
        )
        assert sim_resp_b.status_code == 200
        sim_data_b = sim_resp_b.json()
        assert len(sim_data_b) >= 1
        assert sim_data_b[0]["incident_id"] == str(incident_a.id)

        # Run investigation for Incident B
        updated_b = await investigation_svc.run_investigation(incident_b.id)

        # Verify Incident B resolved
        assert updated_b.status == IncidentStatus.RESOLVED
        assert updated_b.root_cause is not None

        # Check Incident B Postmortem (should reference Incident A)
        pm_resp_b = await client.get(f"/api/v1/incidents/{incident_b.id}/postmortem")
        assert pm_resp_b.status_code == 200
        pm_data_b = pm_resp_b.json()
        assert pm_data_b["incident_id"] == str(incident_b.id)
        assert str(incident_a.id) in pm_data_b["similar_historical_incidents"]

        # Check Incident B Memory record
        mem_resp_b = await client.get(f"/api/v1/incidents/{incident_b.id}/memory")
        assert mem_resp_b.status_code == 200
        assert mem_resp_b.json()["incident_id"] == str(incident_b.id)
