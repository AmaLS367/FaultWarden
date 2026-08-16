"""Incident query and management API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from faultwarden.api.dependencies import get_incident_service, get_investigation_service
from faultwarden.db.models.incident import IncidentModel
from faultwarden.schemas.evidence import EvidenceItem
from faultwarden.schemas.hypothesis import Hypothesis, RootCauseAnalysis
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentFilter,
    IncidentRead,
    IncidentSeverity,
    IncidentStatus,
    InvestigationDetail,
)
from faultwarden.schemas.remediation import RemediationProposal
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


def _build_investigation_detail(incident: IncidentModel) -> InvestigationDetail:
    """Construct a typed InvestigationDetail schema from an IncidentModel database entity."""
    evidence_items = [EvidenceItem.model_validate(e) for e in (incident.evidence or [])]
    hypotheses = [Hypothesis.model_validate(h) for h in (incident.hypotheses or [])]
    root_cause = (
        RootCauseAnalysis.model_validate(incident.root_cause) if incident.root_cause else None
    )
    proposals = [
        RemediationProposal.model_validate(r) for r in (incident.proposed_remediations or [])
    ]
    return InvestigationDetail(
        incident_id=incident.id,
        status=incident.status,
        severity=incident.severity,
        service=incident.service,
        classification=None,
        iteration_count=1,
        evidence=evidence_items,
        hypotheses=hypotheses,
        selected_hypothesis=None,
        root_cause=root_cause,
        remediation_proposals=proposals,
        summary=incident.summary,
        started_at=incident.created_at,
        completed_at=incident.updated_at,
    )


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


@router.get(
    "/{incident_id}/investigation",
    response_model=InvestigationDetail,
    summary="Get Investigation Details",
    description="Fetch the complete AI investigation timeline, hypotheses, root-cause, and remediation proposals.",
)
async def get_incident_investigation(
    incident_id: UUID,
    service: IncidentService = Depends(get_incident_service),
) -> InvestigationDetail:
    """Get detailed investigation state for an incident."""
    incident = await service.get_incident(incident_id)
    return _build_investigation_detail(incident)


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


@router.post(
    "/{incident_id}/investigate",
    response_model=InvestigationDetail,
    summary="Trigger / Retry Investigation",
    description="Manually execute or re-run the autonomous LangGraph investigation workflow for an incident.",
)
async def investigate_incident(
    incident_id: UUID,
    investigation_service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationDetail:
    """Execute investigation workflow on an incident."""
    updated_incident = await investigation_service.run_investigation(incident_id)
    return _build_investigation_detail(updated_incident)
