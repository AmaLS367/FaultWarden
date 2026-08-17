"""Service layer for incident CRUD and lifecycle management."""

from uuid import UUID

from pydantic import TypeAdapter
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.exceptions import IncidentNotFoundError
from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentFilter,
    IncidentStatus,
    IncidentUpdate,
)
from faultwarden.schemas.remediation import RemediationProposal

logger = get_logger("faultwarden.services.incident")


class IncidentService:
    """Encapsulates business operations on incidents."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- Incident Creation ---
    async def create_incident(self, data: IncidentCreate) -> IncidentModel:
        """Create and persist a new incident record."""
        # Convert nested Pydantic models to dicts for JSON storage
        evidence_dicts = [item.model_dump(mode="json") for item in data.evidence]
        hypotheses_dicts = [item.model_dump(mode="json") for item in data.hypotheses]
        root_cause_dict = data.root_cause.model_dump(mode="json") if data.root_cause else None
        remediations_dicts = TypeAdapter(list[RemediationProposal]).dump_python(
            data.proposed_remediations, mode="json"
        )
        classification_dict = (
            data.classification.model_dump(mode="json") if data.classification else None
        )

        incident = IncidentModel(
            title=data.title,
            status=data.status,
            severity=data.severity,
            source=data.source,
            summary=data.summary,
            fingerprint=data.fingerprint,
            service=data.service,
            alert_status=data.alert_status or "firing",
            alert_payload=data.alert_payload,
            evidence=evidence_dicts,
            hypotheses=hypotheses_dicts,
            root_cause=root_cause_dict,
            proposed_remediations=remediations_dicts,
            resolution=data.resolution,
            classification=classification_dict,
            iteration_count=data.iteration_count,
        )

        self.session.add(incident)
        await self.session.flush()
        await self.session.refresh(incident)

        logger.info(
            "incident_created",
            incident_id=str(incident.id),
            title=incident.title,
            fingerprint=incident.fingerprint,
            service=incident.service,
            severity=incident.severity.value
            if hasattr(incident.severity, "value")
            else str(incident.severity),
            status=incident.status.value
            if hasattr(incident.status, "value")
            else str(incident.status),
        )
        return incident

    # --- Incident Lookup & Retrieval ---
    async def find_active_by_fingerprint(self, fingerprint: str) -> IncidentModel | None:
        """Find the latest active (non-resolved) incident matching a given alert fingerprint."""
        stmt = (
            select(IncidentModel)
            .where(
                IncidentModel.fingerprint == fingerprint,
                IncidentModel.status.not_in([IncidentStatus.RESOLVED, IncidentStatus.FAILED]),
            )
            .order_by(desc(IncidentModel.created_at))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_firing_by_fingerprint(self, fingerprint: str) -> IncidentModel | None:
        """Find the latest incident matching a fingerprint whose alert is still actively firing.

        Unlike `find_active_by_fingerprint`, this also excludes incidents whose upstream alert
        already resolved (alert_status == "resolved"): once an alert clears, a later re-firing
        of the same fingerprint is a fresh occurrence and must not be silently absorbed as a
        duplicate update of the old (already-resolved) incident.
        """
        stmt = (
            select(IncidentModel)
            .where(
                IncidentModel.fingerprint == fingerprint,
                IncidentModel.status.not_in([IncidentStatus.RESOLVED, IncidentStatus.FAILED]),
                IncidentModel.alert_status == "firing",
            )
            .order_by(desc(IncidentModel.created_at))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_incident(self, incident_id: UUID | str) -> IncidentModel:
        """Retrieve a single incident by ID or raise IncidentNotFoundError."""
        uuid_val = incident_id if isinstance(incident_id, UUID) else UUID(incident_id)
        stmt = select(IncidentModel).where(IncidentModel.id == uuid_val)
        result = await self.session.execute(stmt)
        incident = result.scalar_one_or_none()

        if incident is None:
            raise IncidentNotFoundError(str(incident_id))

        return incident

    async def list_incidents(self, filters: IncidentFilter | None = None) -> list[IncidentModel]:
        """List incidents with optional filtering and pagination."""
        stmt = select(IncidentModel).order_by(desc(IncidentModel.created_at))

        if filters:
            if filters.status:
                stmt = stmt.where(IncidentModel.status == filters.status)
            if filters.severity:
                stmt = stmt.where(IncidentModel.severity == filters.severity)
            if filters.source:
                stmt = stmt.where(IncidentModel.source == filters.source)
            if filters.fingerprint:
                stmt = stmt.where(IncidentModel.fingerprint == filters.fingerprint)
            if filters.service:
                stmt = stmt.where(IncidentModel.service == filters.service)
            stmt = stmt.limit(filters.limit).offset(filters.offset)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    # --- Incident Updates & Lifecycle Transitions ---
    async def update_incident(
        self, incident_id: UUID | str, update_data: IncidentUpdate
    ) -> IncidentModel:
        """Update incident fields."""
        incident = await self.get_incident(incident_id)

        update_dict = update_data.model_dump(exclude_unset=True)
        if "evidence" in update_dict and update_data.evidence is not None:
            update_dict["evidence"] = [
                item.model_dump(mode="json") for item in update_data.evidence
            ]
        if "hypotheses" in update_dict and update_data.hypotheses is not None:
            update_dict["hypotheses"] = [
                item.model_dump(mode="json") for item in update_data.hypotheses
            ]
        if "root_cause" in update_dict and update_data.root_cause is not None:
            update_dict["root_cause"] = update_data.root_cause.model_dump(mode="json")
        if "proposed_remediations" in update_dict and update_data.proposed_remediations is not None:
            update_dict["proposed_remediations"] = TypeAdapter(
                list[RemediationProposal]
            ).dump_python(update_data.proposed_remediations, mode="json")
        if "classification" in update_dict and update_data.classification is not None:
            update_dict["classification"] = update_data.classification.model_dump(mode="json")
        if "recent_changes" in update_dict and update_data.recent_changes is not None:
            update_dict["recent_changes"] = [
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in update_data.recent_changes
            ]
        if "causal_changes" in update_dict and update_data.causal_changes is not None:
            update_dict["causal_changes"] = [
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in update_data.causal_changes
            ]

        for field, value in update_dict.items():
            setattr(incident, field, value)

        await self.session.flush()
        await self.session.refresh(incident)
        logger.info("incident_updated", incident_id=str(incident.id))
        return incident

    async def transition_status(
        self, incident_id: UUID | str, new_status: IncidentStatus
    ) -> IncidentModel:
        """Transition an incident to a new state."""
        return await self.update_incident(incident_id, IncidentUpdate(status=new_status))
