"""Service layer for executing and persisting LangGraph incident investigations."""

from typing import TYPE_CHECKING, Any
from uuid import UUID

from faultwarden.core.exceptions import FaultWardenError
from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.session import get_session_factory
from faultwarden.graph.builder import build_incident_graph
from faultwarden.schemas.incident import (
    IncidentStatus,
    IncidentUpdate,
)
from faultwarden.services.incident_service import IncidentService

if TYPE_CHECKING:
    from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.services.investigation")


class InvestigationService:
    """Orchestrates LangGraph investigation execution and persists findings into domain models."""

    def __init__(self, incident_service: IncidentService) -> None:
        self.incident_service = incident_service

    # --- Synchronous / Direct Graph Run ---
    async def run_investigation(self, incident_id: UUID | str) -> IncidentModel:
        """Run the complete LangGraph investigation workflow for an incident and persist the result."""
        incident = await self.incident_service.get_incident(incident_id)
        incident_id_str = str(incident.id)

        logger.info("investigation_run_triggered", incident_id=incident_id_str)

        await self.incident_service.transition_status(incident.id, IncidentStatus.INVESTIGATING)

        initial_state: IncidentInvestigationState = {
            "incident_id": incident_id_str,
            "incident_context": {
                "title": incident.title,
                "severity": incident.severity.value
                if hasattr(incident.severity, "value")
                else str(incident.severity),
                "service": incident.service or "unknown",
            },
            "alert": incident.alert_payload or {},
            "evidence": [],
            "metrics": [],
            "logs": [],
            "traces": [],
            "recent_changes": [],
            "hypotheses": [],
            "selected_hypothesis": None,
            "root_cause": None,
            "remediation_proposals": [],
            "iteration_count": 1,
            "investigation_status": "INVESTIGATING",
            "missing_evidence_queries": [],
            "summary": "",
            "errors": [],
        }

        graph = build_incident_graph()

        try:
            final_state: dict[str, Any] = await graph.ainvoke(initial_state)

            evidence_items = final_state.get("evidence", [])
            hypotheses_list = final_state.get("hypotheses", [])
            root_cause_val = final_state.get("root_cause")
            proposals_list = final_state.get("remediation_proposals", [])
            summary_val = final_state.get("summary", "")

            if proposals_list:
                next_status = IncidentStatus.REMEDIATION_PROPOSED
            elif root_cause_val:
                next_status = IncidentStatus.ROOT_CAUSE_IDENTIFIED
            else:
                next_status = IncidentStatus.INVESTIGATING

            update_data = IncidentUpdate(
                status=next_status,
                evidence=evidence_items,
                hypotheses=hypotheses_list,
                root_cause=root_cause_val,
                proposed_remediations=proposals_list,
                summary=summary_val or incident.summary,
            )

            updated_incident = await self.incident_service.update_incident(incident.id, update_data)

            logger.info(
                "investigation_run_completed",
                incident_id=incident_id_str,
                status=next_status.value,
                evidence_count=len(evidence_items),
                hypotheses_count=len(hypotheses_list),
                has_root_cause=root_cause_val is not None,
            )

            return updated_incident

        except Exception as exc:
            logger.error(
                "investigation_run_failed",
                incident_id=incident_id_str,
                error=str(exc),
            )
            # Write the failure record through a fresh session so it survives regardless of
            # how the caller's own transaction resolves (it will roll back on this exception).
            try:
                fail_summary = f"Investigation failed with error: {exc}"
                session_factory = get_session_factory()
                async with session_factory() as fail_session, fail_session.begin():
                    fail_service = IncidentService(fail_session)
                    await fail_service.update_incident(
                        incident.id,
                        IncidentUpdate(
                            status=IncidentStatus.FAILED,
                            summary=fail_summary,
                        ),
                    )
            except Exception as write_exc:
                logger.error(
                    "investigation_failure_record_write_failed",
                    incident_id=incident_id_str,
                    error=str(write_exc),
                )
            raise FaultWardenError(f"Investigation execution failed: {exc}") from exc


# --- Background Investigation Worker ---
async def run_background_investigation(incident_id: UUID | str) -> None:
    """Run an investigation inside an isolated DB session, intended for FastAPI BackgroundTasks."""
    logger.info("launching_background_investigation", incident_id=str(incident_id))
    session_factory = get_session_factory()
    try:
        async with session_factory() as session, session.begin():
            incident_service = IncidentService(session)
            investigation_service = InvestigationService(incident_service)
            await investigation_service.run_investigation(incident_id)
    except Exception as exc:
        logger.error(
            "background_investigation_error",
            incident_id=str(incident_id),
            error=str(exc),
        )
