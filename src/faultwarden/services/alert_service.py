"""Service for processing Alertmanager webhooks and ingesting alerts."""

from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.schemas.alert import AlertIngestResponse, AlertmanagerPayload
from faultwarden.schemas.incident import IncidentCreate, IncidentSeverity, IncidentStatus
from faultwarden.services.incident_service import IncidentService

logger = get_logger("faultwarden.services.alert")


class AlertService:
    """Handles incoming observability alerts and creates corresponding incidents."""

    def __init__(self, incident_service: IncidentService) -> None:
        self.incident_service = incident_service

    async def process_alertmanager_webhook(
        self, payload: AlertmanagerPayload
    ) -> tuple[IncidentModel, AlertIngestResponse]:
        """Convert an Alertmanager webhook payload into a tracked incident."""
        logger.info(
            "alertmanager_webhook_received",
            status=payload.status,
            group_key=payload.groupKey,
            alerts_count=len(payload.alerts),
        )

        alert_name = payload.primary_alertname
        raw_severity = payload.primary_severity
        severity_map = {
            "CRITICAL": IncidentSeverity.CRITICAL,
            "HIGH": IncidentSeverity.HIGH,
            "WARNING": IncidentSeverity.MEDIUM,
            "MEDIUM": IncidentSeverity.MEDIUM,
            "LOW": IncidentSeverity.LOW,
            "INFO": IncidentSeverity.INFO,
        }
        severity = severity_map.get(raw_severity, IncidentSeverity.MEDIUM)

        description = payload.commonAnnotations.get(
            "description",
            payload.commonAnnotations.get("summary", f"Alertmanager alert {alert_name}"),
        )
        service_name = payload.commonLabels.get(
            "job", payload.commonLabels.get("service", "unknown-service")
        )

        title = f"[{severity.value}] {alert_name} in {service_name}"
        summary = f"Alertmanager group '{payload.groupKey}' triggered with status '{payload.status}'. {description}"

        incident_create = IncidentCreate(
            title=title,
            status=IncidentStatus.DETECTED,
            severity=severity,
            source="alertmanager",
            summary=summary,
            alert_payload=payload.model_dump(mode="json"),
        )

        incident = await self.incident_service.create_incident(incident_create)

        # Integration Point: In v0.1+ async LangGraph workflow execution will be dispatched here.

        response = AlertIngestResponse(
            status="received",
            incident_id=str(incident.id),
            incident_title=incident.title,
            incident_status=incident.status.value
            if hasattr(incident.status, "value")
            else str(incident.status),
            alerts_count=len(payload.alerts),
        )

        return incident, response
