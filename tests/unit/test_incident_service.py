"""Unit tests for IncidentService operations and lifecycle."""

from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.exceptions import IncidentNotFoundError
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentFilter,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)
from faultwarden.services.incident_service import IncidentService


# --- Incident Service Tests ---
@pytest.mark.asyncio
async def test_incident_service_crud_and_status_transitions(db_session: AsyncSession) -> None:
    """Test creating, fetching, updating, filtering, and transitioning incidents in DB."""
    service = IncidentService(session=db_session)

    # - 1. Creation & Active Lookup
    create_dto = IncidentCreate(
        title="Test Database Latency Spike",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.HIGH,
        source="manual",
        summary="Database query response latency exceeded 500ms threshold.",
        fingerprint="fp-db-latency-001",
        service="db-service",
        alert_status="firing",
    )
    incident = await service.create_incident(create_dto)
    assert incident.id is not None
    assert incident.title == "Test Database Latency Spike"
    assert incident.status == IncidentStatus.DETECTED
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.fingerprint == "fp-db-latency-001"
    assert incident.service == "db-service"
    assert incident.alert_status == "firing"

    found_by_fp = await service.find_active_by_fingerprint("fp-db-latency-001")
    assert found_by_fp is not None
    assert found_by_fp.id == incident.id

    # - 2. ID Lookup & Mutations
    fetched = await service.get_incident(incident.id)
    assert fetched.id == incident.id
    assert fetched.title == incident.title

    updated = await service.update_incident(
        incident.id,
        IncidentUpdate(
            status=IncidentStatus.INVESTIGATING,
            summary="Investigation underway with Prometheus metrics.",
            alert_status="firing",
        ),
    )
    assert updated.status == IncidentStatus.INVESTIGATING
    assert updated.summary == "Investigation underway with Prometheus metrics."

    # - 3. State Transitions & Resolution Invariants
    transitioned = await service.transition_status(incident.id, IncidentStatus.RESOLVED)
    assert transitioned.status == IncidentStatus.RESOLVED

    # After resolution, active search by fingerprint returns None so new alert creates a separate incident
    resolved_active_search = await service.find_active_by_fingerprint("fp-db-latency-001")
    assert resolved_active_search is None

    # - 4. Filtering & Error Handling
    results = await service.list_incidents(
        IncidentFilter(status=IncidentStatus.RESOLVED, fingerprint="fp-db-latency-001")
    )
    assert len(results) >= 1
    assert any(r.id == incident.id for r in results)

    empty_results = await service.list_incidents(IncidentFilter(status=IncidentStatus.FAILED))
    assert len(empty_results) == 0

    fake_id = uuid4()
    with pytest.raises(IncidentNotFoundError):
        await service.get_incident(fake_id)
