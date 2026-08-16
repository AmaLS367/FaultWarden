"""Service for processing Alertmanager webhooks and ingesting alerts."""

from fastapi import BackgroundTasks

from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.schemas.alert import AlertIngestResponse, AlertmanagerPayload
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import run_background_investigation

logger = get_logger("faultwarden.services.alert")

# --- Severity Mapping ---
_SEVERITY_MAP: dict[str, IncidentSeverity] = {
    "CRITICAL": IncidentSeverity.CRITICAL,
    "HIGH": IncidentSeverity.HIGH,
    "WARNING": IncidentSeverity.MEDIUM,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "LOW": IncidentSeverity.LOW,
    "INFO": IncidentSeverity.INFO,
}


class AlertService:
    """Handles incoming observability alerts and creates corresponding incidents."""

    def __init__(self, incident_service: IncidentService) -> None:
        self.incident_service = incident_service

    # --- Public Ingestion API ---
    async def process_alertmanager_webhook(
        self,
        payload: AlertmanagerPayload,
        background_tasks: BackgroundTasks,
        auto_investigate: bool = True,
    ) -> tuple[IncidentModel, AlertIngestResponse]:
        """Convert an Alertmanager webhook payload into a tracked incident idempotently."""
        fingerprint = payload.primary_fingerprint
        service_name = payload.primary_service
        alert_name = payload.primary_alertname
        raw_severity = payload.primary_severity
        severity = _SEVERITY_MAP.get(raw_severity, IncidentSeverity.MEDIUM)

        logger.info(
            "alert_received",
            status=payload.status,
            alert_fingerprint=fingerprint,
            service=service_name,
            alertname=alert_name,
            group_key=payload.groupKey,
            alerts_count=len(payload.alerts),
        )

        description = payload.commonAnnotations.get(
            "description",
            payload.commonAnnotations.get("summary", f"Alertmanager alert {alert_name}"),
        )
        title = f"[{severity.value}] {alert_name} in {service_name}"
        summary = f"Alertmanager group '{payload.groupKey}' triggered with status '{payload.status}'. {description}"

        if payload.is_resolved:
            return await self._handle_resolved_alert(
                payload=payload,
                fingerprint=fingerprint,
                service_name=service_name,
                title=title,
                severity=severity,
                summary=summary,
            )

        return await self._handle_firing_alert(
            payload=payload,
            fingerprint=fingerprint,
            service_name=service_name,
            title=title,
            severity=severity,
            summary=summary,
            background_tasks=background_tasks,
            auto_investigate=auto_investigate,
        )

    # --- Private Handlers ---
    async def _handle_firing_alert(
        self,
        payload: AlertmanagerPayload,
        fingerprint: str,
        service_name: str,
        title: str,
        severity: IncidentSeverity,
        summary: str,
        background_tasks: BackgroundTasks,
        auto_investigate: bool = True,
    ) -> tuple[IncidentModel, AlertIngestResponse]:
        """Process firing alerts idempotently by checking for an active incident fingerprint."""
        # We match incoming alerts via unique fingerprints to identify recurring issues
        existing_incident = await self.incident_service.find_active_by_fingerprint(fingerprint)

        if existing_incident is not None:
            # Prevent notification storms from creating duplicate incidents for the same active condition
            logger.info(
                "duplicate_alert_received",
                incident_id=str(existing_incident.id),
                alert_fingerprint=fingerprint,
                service=service_name,
                severity=severity.value,
            )
            update_data = IncidentUpdate(
                alert_payload=payload.model_dump(mode="json"),
                alert_status="firing",
                summary=summary,
            )
            incident = await self.incident_service.update_incident(
                existing_incident.id, update_data
            )
            logger.info(
                "incident_updated",
                incident_id=str(incident.id),
                alert_fingerprint=fingerprint,
                service=service_name,
                severity=severity.value,
            )
            response_status = "updated"
        else:
            # First occurrence of this active alert condition spawns a new tracked incident
            incident_create = IncidentCreate(
                title=title,
                status=IncidentStatus.DETECTED,
                severity=severity,
                source="alertmanager",
                summary=summary,
                fingerprint=fingerprint,
                service=service_name,
                alert_status="firing",
                alert_payload=payload.model_dump(mode="json"),
            )
            incident = await self.incident_service.create_incident(incident_create)
            logger.info(
                "incident_created",
                incident_id=str(incident.id),
                alert_fingerprint=fingerprint,
                service=service_name,
                severity=severity.value,
            )
            response_status = "created"

            # Launch non-blocking background investigation without delaying webhook response.
            # BackgroundTasks runs this only after the response (and thus the session commit
            # in get_db_session) has completed, so the incident row is guaranteed visible.
            if auto_investigate:
                background_tasks.add_task(run_background_investigation, incident.id)

        response = AlertIngestResponse(
            status=response_status,
            incident_id=str(incident.id),
            incident_title=incident.title,
            incident_status=incident.status.value
            if hasattr(incident.status, "value")
            else str(incident.status),
            alerts_count=len(payload.alerts),
            fingerprint=fingerprint,
        )
        return incident, response

    async def _handle_resolved_alert(
        self,
        payload: AlertmanagerPayload,
        fingerprint: str,
        service_name: str,
        title: str,
        severity: IncidentSeverity,
        summary: str,
    ) -> tuple[IncidentModel, AlertIngestResponse]:
        """Record detection alert recovery without prematurely closing the domain incident."""
        existing_incident = await self.incident_service.find_active_by_fingerprint(fingerprint)

        if existing_incident is not None:
            # Metric clearance indicates symptoms stopped but incident requires autonomous verification.
            # We do not close the incident here to allow for post-incident review and confirmation.
            update_data = IncidentUpdate(
                alert_status="resolved",
                alert_payload=payload.model_dump(mode="json"),
            )
            incident = await self.incident_service.update_incident(
                existing_incident.id, update_data
            )
            logger.info(
                "alert_resolved",
                incident_id=str(incident.id),
                alert_fingerprint=fingerprint,
                service=service_name,
            )
            response_status = "alert_resolved"
        else:
            # Record unlinked resolved notification for post-mortem auditability. Created
            # already-RESOLVED (not DETECTED) since there is no active condition to track —
            # a live status here would otherwise permanently block the next real firing alert
            # on this fingerprint from starting a fresh investigation.
            logger.info(
                "alert_resolved_unmatched",
                alert_fingerprint=fingerprint,
                service=service_name,
            )
            incident_create = IncidentCreate(
                title=title,
                status=IncidentStatus.RESOLVED,
                severity=severity,
                source="alertmanager",
                summary=summary,
                fingerprint=fingerprint,
                service=service_name,
                alert_status="resolved",
                alert_payload=payload.model_dump(mode="json"),
            )
            incident = await self.incident_service.create_incident(incident_create)
            response_status = "alert_resolved"

        response = AlertIngestResponse(
            status=response_status,
            incident_id=str(incident.id),
            incident_title=incident.title,
            incident_status=incident.status.value
            if hasattr(incident.status, "value")
            else str(incident.status),
            alerts_count=len(payload.alerts),
            fingerprint=fingerprint,
        )
        return incident, response
