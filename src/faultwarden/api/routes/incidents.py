from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import TypeAdapter
from sqlalchemy import select

from faultwarden.api.dependencies import (
    get_incident_service,
    get_investigation_service,
    get_memory_service,
    get_postmortem_service,
)
from faultwarden.core.exceptions import (
    ActiveJobConflictError,
    IncidentMemoryNotFoundError,
    PostmortemNotFoundError,
)
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.job import InvestigationJobModel
from faultwarden.schemas.change import OperationalChange
from faultwarden.schemas.classification import IncidentClassification
from faultwarden.schemas.evidence import EvidenceItem
from faultwarden.schemas.hypothesis import Hypothesis, HypothesisStatus, RootCauseAnalysis
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentFilter,
    IncidentRead,
    IncidentSeverity,
    IncidentStatus,
    InvestigationDetail,
)
from faultwarden.schemas.job import InvestigationJobStatus
from faultwarden.schemas.memory import IncidentMemory, SimilarIncidentMemory
from faultwarden.schemas.postmortem import IncidentPostmortem
from faultwarden.schemas.remediation import RemediationProposal
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService
from faultwarden.services.memory_service import MemoryService
from faultwarden.services.postmortem_service import PostmortemService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


def _select_hypothesis(
    hypotheses: list[Hypothesis], root_cause: RootCauseAnalysis | None
) -> Hypothesis | None:
    """Derive the winning hypothesis from the persisted list, since it isn't stored separately."""
    if not hypotheses:
        return None
    if root_cause is not None:
        for hyp in hypotheses:
            if hyp.id == root_cause.primary_hypothesis_id:
                return hyp
    for hyp in hypotheses:
        if hyp.status == HypothesisStatus.VERIFIED:
            return hyp
    inconclusive_hypotheses = [h for h in hypotheses if h.status == HypothesisStatus.INCONCLUSIVE]
    if inconclusive_hypotheses:
        return max(inconclusive_hypotheses, key=lambda h: h.confidence_score)
    return max(hypotheses, key=lambda h: h.confidence_score)


def _build_investigation_detail(incident: IncidentModel) -> InvestigationDetail:
    """Construct a typed InvestigationDetail schema from an IncidentModel database entity."""
    evidence_items = [EvidenceItem.model_validate(e) for e in (incident.evidence or [])]
    hypotheses = [Hypothesis.model_validate(h) for h in (incident.hypotheses or [])]
    root_cause = (
        RootCauseAnalysis.model_validate(incident.root_cause) if incident.root_cause else None
    )
    proposals = TypeAdapter(list[RemediationProposal]).validate_python(
        incident.proposed_remediations or []
    )
    classification = (
        IncidentClassification.model_validate(incident.classification)
        if incident.classification
        else None
    )
    recent_changes = [OperationalChange.model_validate(c) for c in (incident.recent_changes or [])]
    candidate_causal_changes = [
        OperationalChange.model_validate(c)
        for c in (getattr(incident, "candidate_causal_changes", None) or [])
    ]
    verified_causal_changes = [
        OperationalChange.model_validate(c) for c in (incident.causal_changes or [])
    ]
    selected_causal_change: OperationalChange | None = None
    if verified_causal_changes:
        selected_causal_change = verified_causal_changes[0]
    elif root_cause and root_cause.causal_change_ids:
        all_known = {c.id: c for c in (recent_changes + candidate_causal_changes)}
        for cid in root_cause.causal_change_ids:
            if cid in all_known:
                selected_causal_change = all_known[cid]
                break
    return InvestigationDetail(
        incident_id=incident.id,
        status=incident.status,
        severity=incident.severity,
        service=incident.service,
        classification=classification,
        iteration_count=incident.iteration_count,
        evidence=evidence_items,
        hypotheses=hypotheses,
        selected_hypothesis=_select_hypothesis(hypotheses, root_cause),
        root_cause=root_cause,
        remediation_proposals=proposals,
        recent_changes=recent_changes,
        candidate_causal_changes=candidate_causal_changes,
        selected_causal_change=selected_causal_change,
        summary=incident.summary,
        started_at=incident.created_at,
        completed_at=incident.updated_at
        if incident.status in [IncidentStatus.RESOLVED, IncidentStatus.FAILED]
        else None,
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
    incident_service: IncidentService = Depends(get_incident_service),
) -> InvestigationDetail:
    """Execute investigation workflow on an incident, checking for active job conflicts."""
    # Check if there is an active job running for this incident under an unexpired lease
    now = datetime.now(UTC)
    stmt = (
        select(InvestigationJobModel)
        .where(
            InvestigationJobModel.incident_id == incident_id,
            InvestigationJobModel.status == InvestigationJobStatus.RUNNING,
            InvestigationJobModel.lease_expires_at > now,
        )
        .limit(1)
    )
    res = await incident_service.session.execute(stmt)
    active_job = res.scalar_one_or_none()
    if active_job is not None:
        raise ActiveJobConflictError(
            incident_id=str(incident_id),
            job_id=str(active_job.id),
            job_status=active_job.status.value,
        )

    updated_incident = await investigation_service.run_investigation(incident_id)
    return _build_investigation_detail(updated_incident)


# --- Postmortem & Incident Memory Routes ---
@router.get(
    "/{incident_id}/postmortem",
    response_model=IncidentPostmortem,
    summary="Get Incident Postmortem",
    description="Retrieve the generated postmortem analysis for a resolved incident.",
)
async def get_incident_postmortem(
    incident_id: UUID,
    postmortem_service: PostmortemService = Depends(get_postmortem_service),
) -> IncidentPostmortem:
    """Fetch structured postmortem for an incident."""
    postmortem_model = await postmortem_service.get_postmortem_by_incident_id(incident_id)
    if postmortem_model is None:
        raise PostmortemNotFoundError(incident_id=str(incident_id))
    return IncidentPostmortem.model_validate(postmortem_model)


@router.get(
    "/{incident_id}/memory",
    response_model=IncidentMemory,
    summary="Get Incident Memory",
    description="Retrieve the compact vector memory record for an incident.",
)
async def get_incident_memory(
    incident_id: UUID,
    memory_service: MemoryService = Depends(get_memory_service),
) -> IncidentMemory:
    """Fetch compact memory record for an incident."""
    memory_model = await memory_service.get_memory_by_incident_id(incident_id)
    if memory_model is None:
        raise IncidentMemoryNotFoundError(incident_id=str(incident_id))
    return IncidentMemory.model_validate(memory_model)


@router.get(
    "/{incident_id}/similar",
    response_model=list[SimilarIncidentMemory],
    summary="Find Similar Incidents",
    description="Retrieve historically similar resolved incidents based on the current incident's context.",
)
async def get_similar_incidents(
    incident_id: UUID,
    limit: int = Query(
        5, ge=1, le=20, description="Maximum number of similar incidents to return."
    ),
    min_similarity: float = Query(
        0.3, ge=0.0, le=1.0, description="Minimum cosine similarity threshold."
    ),
    incident_service: IncidentService = Depends(get_incident_service),
    memory_service: MemoryService = Depends(get_memory_service),
) -> list[SimilarIncidentMemory]:
    """Find historically similar resolved incidents for a given incident."""
    incident = await incident_service.get_incident(incident_id)
    alert_info = incident.alert_payload or {}
    ann = alert_info.get("commonAnnotations", {})
    symptoms = ann.get("summary") or ann.get("description") or incident.summary or incident.title
    category = "UNKNOWN"
    if incident.classification and isinstance(incident.classification, dict):
        category = incident.classification.get("category", "UNKNOWN")

    query = (
        f"Service: {incident.service or 'unknown'}\n"
        f"Classification: {category}\n"
        f"Symptoms: {symptoms}"
    )
    return await memory_service.search_similar(
        query=query,
        service=None,
        limit=limit,
        min_similarity=min_similarity,
        exclude_incident_id=incident_id,
    )


# --- Change Intelligence Routes ---
@router.get(
    "/{incident_id}/changes",
    response_model=list[OperationalChange],
    summary="Get Recent Incident Changes",
    description="Retrieve bounded recent deployments, git commits, and config changes collected for the incident.",
)
async def get_incident_changes(
    incident_id: UUID,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[OperationalChange]:
    """Fetch recent operational changes associated with an incident."""
    incident = await incident_service.get_incident(incident_id)
    return [OperationalChange.model_validate(c) for c in (incident.recent_changes or [])]


@router.get(
    "/{incident_id}/causal-changes",
    response_model=list[OperationalChange],
    summary="Get Verified Causal Incident Changes",
    description="Retrieve verified causal changes confirmed by deterministic correlation and telemetry evidence gates to have directly contributed to or induced the incident.",
)
async def get_incident_causal_changes(
    incident_id: UUID,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[OperationalChange]:
    """Fetch strictly verified causal operational changes for an incident."""
    incident = await incident_service.get_incident(incident_id)
    causal_changes = [OperationalChange.model_validate(c) for c in (incident.causal_changes or [])]
    if not causal_changes and incident.root_cause and incident.root_cause.get("causal_change_ids"):
        # Match causal_change_ids against recent_changes
        recent = [OperationalChange.model_validate(c) for c in (incident.recent_changes or [])]
        causal_ids = set(incident.root_cause["causal_change_ids"])
        causal_changes = [c for c in recent if c.id in causal_ids]
    return causal_changes
