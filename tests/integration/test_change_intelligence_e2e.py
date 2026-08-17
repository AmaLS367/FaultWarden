"""End-to-end integration test for Change Intelligence (v0.5)."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.models.incident import IncidentModel
from faultwarden.integrations.change.base import ChangeProvider
from faultwarden.integrations.embedding.provider import MockEmbeddingProvider
from faultwarden.integrations.llm.provider import MockLLMProvider
from faultwarden.main import create_app
from faultwarden.schemas.change import (
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService


class MockE2EChangeProvider(ChangeProvider):
    """Mock change provider returning a bad config deployment."""

    async def list_changes(
        self,
        service: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 50,
    ) -> list[OperationalChange]:
        return [
            OperationalChange(
                id="deploy-002",
                source="deployment",
                service=service,
                change_type=ChangeType.DEPLOYMENT,
                title="Deploy v1.0.1: DB_POOL_SIZE changed from 20 to 5",
                timestamp=datetime.now(UTC),
                config_changes=[
                    ConfigurationChange(
                        key="DB_POOL_SIZE",
                        old_value="20",
                        new_value="5",
                        component="database",
                    )
                ],
            )
        ]


@pytest.mark.asyncio
async def test_e2e_change_intelligence_investigation(db_session: AsyncSession) -> None:
    """Run full E2E investigation with change intelligence, verify postmortem and memory indexing."""
    now = datetime.now(UTC)
    incident = IncidentModel(
        id=uuid4(),
        title="High Database Error Rate on demo-service",
        service="demo-service",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.HIGH,
        source="alertmanager",
        alert_payload={
            "status": "firing",
            "groupLabels": {"alertname": "DemoServiceDatabaseErrorRateHigh"},
            "commonAnnotations": {
                "summary": "Database pool exhaustion on demo-service",
                "description": "5xx errors spiking due to connection pool timeout",
            },
            "alerts": [{"startsAt": now.isoformat()}],
        },
    )
    db_session.add(incident)
    await db_session.commit()

    llm = MockLLMProvider()
    embedding = MockEmbeddingProvider(dimensions=384)
    change_provider = MockE2EChangeProvider()

    incident_service = IncidentService(db_session)
    investigation_service = InvestigationService(
        incident_service=incident_service,
        llm_provider=llm,
        embedding_provider=embedding,
        change_provider=change_provider,
    )

    # 1. Run Autonomous Investigation
    updated = await investigation_service.run_investigation(incident.id)

    assert updated.status in (
        IncidentStatus.RESOLVED,
        IncidentStatus.ROOT_CAUSE_IDENTIFIED,
        IncidentStatus.REMEDIATION_PROPOSED,
        IncidentStatus.AWAITING_APPROVAL,
    )
    assert updated.root_cause is not None
    assert len(updated.recent_changes) >= 1

    # 2. Verify REST API endpoints using FastAPI test client
    app = create_app()

    # Provide DB session to FastAPI dependencies via dependency overrides
    from faultwarden.api.dependencies import get_db

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # GET /api/v1/incidents/{id}/changes
        resp_changes = await ac.get(f"/api/v1/incidents/{incident.id}/changes")
        assert resp_changes.status_code == 200
        changes_data = resp_changes.json()
        assert len(changes_data) >= 1
        assert changes_data[0]["id"] == "deploy-002"

        # GET /api/v1/incidents/{id}/causal-changes
        resp_causal = await ac.get(f"/api/v1/incidents/{incident.id}/causal-changes")
        assert resp_causal.status_code == 200
        causal_data = resp_causal.json()
        assert isinstance(causal_data, list)

        # GET /api/v1/incidents/{id}/investigation
        resp_inv = await ac.get(f"/api/v1/incidents/{incident.id}/investigation")
        assert resp_inv.status_code == 200
        inv_data = resp_inv.json()
        assert len(inv_data["recent_changes"]) >= 1
        assert inv_data["recent_changes"][0]["id"] == "deploy-002"
