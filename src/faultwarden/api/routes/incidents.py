"""Incident query and management API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from faultwarden.api.dependencies import get_incident_service
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentFilter,
    IncidentRead,
    IncidentSeverity,
    IncidentStatus,
)
from faultwarden.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


# --- Query Routes ---
@router.get(
    "",
    response_model=list[IncidentRead],
    summary="List Incidents",
    description="Retrieve a paginated list of incidents with optional status, severity, and source filtering.",
)
async def list_incidents(
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity_filter: IncidentSeverity | None = Query(default=None, alias="severity"),
    source: str | None = Query(default=None),
    fingerprint: str | None = Query(default=None),
    service_name: str | None = Query(default=None, alias="service"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    service: IncidentService = Depends(get_incident_service),
) -> list[IncidentRead]:
    """List recorded incidents."""
    filters = IncidentFilter(
        status=status_filter,
        severity=severity_filter,
        source=source,
        fingerprint=fingerprint,
        service=service_name,
        limit=limit,
        offset=offset,
    )
    incidents = await service.list_incidents(filters)
    return [IncidentRead.model_validate(inc) for inc in incidents]


@router.get(
    "/{incident_id}",
    response_model=IncidentRead,
    summary="Get Incident Details",
    description="Fetch a single incident by its unique UUID.",
)
async def get_incident(
    incident_id: UUID,
    service: IncidentService = Depends(get_incident_service),
) -> IncidentRead:
    """Get single incident by ID."""
    incident = await service.get_incident(incident_id)
    return IncidentRead.model_validate(incident)


# --- Mutation Routes ---
@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=IncidentRead,
    summary="Create Incident Manually",
    description="Manually create a new incident record.",
)
async def create_incident(
    data: IncidentCreate,
    service: IncidentService = Depends(get_incident_service),
) -> IncidentRead:
    """Manually create incident."""
    incident = await service.create_incident(data)
    return IncidentRead.model_validate(incident)
