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


@pytest.mark.asyncio
async def test_incident_service_crud_and_status_transitions(db_session: AsyncSession) -> None:
    """Test creating, fetching, updating, filtering, and transitioning incidents in DB."""
    service = IncidentService(session=db_session)

    # 1. Create incident
    create_dto = IncidentCreate(
        title="Test Database Latency Spike",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.HIGH,
        source="manual",
        summary="Database query response latency exceeded 500ms threshold.",
    )
    incident = await service.create_incident(create_dto)
    assert incident.id is not None
    assert incident.title == "Test Database Latency Spike"
    assert incident.status == IncidentStatus.DETECTED
    assert incident.severity == IncidentSeverity.HIGH

    # 2. Get incident by UUID
    fetched = await service.get_incident(incident.id)
    assert fetched.id == incident.id
    assert fetched.title == incident.title

    # 3. Update incident
    updated = await service.update_incident(
        incident.id,
        IncidentUpdate(
            status=IncidentStatus.INVESTIGATING,
            summary="Investigation underway with Prometheus metrics.",
        ),
    )
    assert updated.status == IncidentStatus.INVESTIGATING
    assert updated.summary == "Investigation underway with Prometheus metrics."

    # 4. Transition status
    transitioned = await service.transition_status(incident.id, IncidentStatus.RESOLVED)
    assert transitioned.status == IncidentStatus.RESOLVED

    # 5. List with filters
    results = await service.list_incidents(IncidentFilter(status=IncidentStatus.RESOLVED))
    assert len(results) >= 1
    assert any(r.id == incident.id for r in results)

    # Filter with no match
    empty_results = await service.list_incidents(IncidentFilter(status=IncidentStatus.FAILED))
    assert len(empty_results) == 0

    # 6. Not found error
    fake_id = uuid4()
    with pytest.raises(IncidentNotFoundError):
        await service.get_incident(fake_id)
