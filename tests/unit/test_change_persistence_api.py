"""Unit tests for change persistence and REST API semantics (v0.5.1)."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.api.dependencies import get_db
from faultwarden.db.models.incident import IncidentModel
from faultwarden.main import create_app
from faultwarden.schemas.change import (
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)
from faultwarden.schemas.hypothesis import RootCauseAnalysis
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus


@pytest.mark.asyncio
async def test_candidate_vs_verified_causal_changes_persistence_and_api(
    db_session: AsyncSession,
) -> None:
    """Test candidate changes vs verified causal changes API separation."""
    now = datetime.now(UTC)

    candidate_ch = OperationalChange(
        id="deploy-candidate-only",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Candidate deployment that was not verified as causal",
        timestamp=now,
    )

    verified_ch = OperationalChange(
        id="deploy-verified-causal",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Verified causal deployment: DB_POOL_SIZE 20 -> 5",
        timestamp=now,
        config_changes=[ConfigurationChange(key="DB_POOL_SIZE", old_value="20", new_value="5")],
    )

    root_cause = RootCauseAnalysis(
        primary_hypothesis_id=str(uuid4()),
        summary="Database pool exhaustion verified",
        root_cause_category="RESOURCE_EXHAUSTION",
        culprit_service="demo-service",
        causal_change_ids=["deploy-verified-causal"],
        causal_change_summary="deploy-verified-causal: DB_POOL_SIZE 20 -> 5",
        confidence=0.95,
    )

    incident = IncidentModel(
        id=uuid4(),
        title="High error rate on demo-service",
        service="demo-service",
        status=IncidentStatus.ROOT_CAUSE_IDENTIFIED,
        severity=IncidentSeverity.HIGH,
        source="alertmanager",
        recent_changes=[candidate_ch.model_dump(mode="json"), verified_ch.model_dump(mode="json")],
        candidate_causal_changes=[
            candidate_ch.model_dump(mode="json"),
            verified_ch.model_dump(mode="json"),
        ],
        causal_changes=[verified_ch.model_dump(mode="json")],  # Strictly verified
        root_cause=root_cause.model_dump(mode="json"),
    )
    db_session.add(incident)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. GET /api/v1/incidents/{id}/changes returns all recent changes (both)
        resp_changes = await ac.get(f"/api/v1/incidents/{incident.id}/changes")
        assert resp_changes.status_code == 200
        changes_data = resp_changes.json()
        assert len(changes_data) == 2
        change_ids = {c["id"] for c in changes_data}
        assert "deploy-candidate-only" in change_ids
        assert "deploy-verified-causal" in change_ids

        # 2. GET /api/v1/incidents/{id}/causal-changes returns ONLY verified causal change
        resp_causal = await ac.get(f"/api/v1/incidents/{incident.id}/causal-changes")
        assert resp_causal.status_code == 200
        causal_data = resp_causal.json()
        assert len(causal_data) == 1
        assert causal_data[0]["id"] == "deploy-verified-causal"
        # Candidate-only change is NOT in causal changes!
        assert all(c["id"] != "deploy-candidate-only" for c in causal_data)

        # 3. GET /api/v1/incidents/{id}/investigation includes candidate and selected
        resp_inv = await ac.get(f"/api/v1/incidents/{incident.id}/investigation")
        assert resp_inv.status_code == 200
        inv_data = resp_inv.json()
        assert len(inv_data["recent_changes"]) == 2
        assert len(inv_data["candidate_causal_changes"]) == 2
        assert inv_data["selected_causal_change"] is not None
        assert inv_data["selected_causal_change"]["id"] == "deploy-verified-causal"


@pytest.mark.asyncio
async def test_root_cause_with_no_verified_causal_change_is_valid(
    db_session: AsyncSession,
) -> None:
    """Test incident with verified root cause but NO causal changes."""
    root_cause = RootCauseAnalysis(
        primary_hypothesis_id=str(uuid4()),
        summary="External third-party API outage",
        root_cause_category="DEPENDENCY_FAILURE",
        culprit_service="demo-service",
        causal_change_ids=[],  # No verified causal change
        causal_change_summary=None,
        confidence=0.90,
    )

    incident = IncidentModel(
        id=uuid4(),
        title="Third-party payment gateway timeout",
        service="demo-service",
        status=IncidentStatus.ROOT_CAUSE_IDENTIFIED,
        severity=IncidentSeverity.MEDIUM,
        source="alertmanager",
        recent_changes=[],
        candidate_causal_changes=[],
        causal_changes=[],
        root_cause=root_cause.model_dump(mode="json"),
    )
    db_session.add(incident)
    await db_session.commit()

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp_causal = await ac.get(f"/api/v1/incidents/{incident.id}/causal-changes")
        assert resp_causal.status_code == 200
        causal_data = resp_causal.json()
        assert causal_data == []
