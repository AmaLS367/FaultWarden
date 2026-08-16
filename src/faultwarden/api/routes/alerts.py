"""Alert ingestion API routes."""

from fastapi import APIRouter, BackgroundTasks, Depends, status

from faultwarden.api.dependencies import get_alert_service
from faultwarden.schemas.alert import AlertIngestResponse, AlertmanagerPayload
from faultwarden.services.alert_service import AlertService
from faultwarden.telemetry.setup import INCIDENTS_CREATED_TOTAL

router = APIRouter(prefix="/alerts", tags=["Alerts"])


# --- Ingestion Webhooks ---
@router.post(
    "/alertmanager",
    status_code=status.HTTP_201_CREATED,
    response_model=AlertIngestResponse,
    summary="Ingest Alertmanager Webhook",
    description="Receives firing/resolved alerts from Prometheus Alertmanager and creates a tracked incident.",
)
async def ingest_alertmanager_alert(
    payload: AlertmanagerPayload,
    background_tasks: BackgroundTasks,
    alert_service: AlertService = Depends(get_alert_service),
) -> AlertIngestResponse:
    """Ingest webhook from Alertmanager and create Incident."""
    incident, response = await alert_service.process_alertmanager_webhook(
        payload, background_tasks=background_tasks
    )
    # Only increment creation counter for new incidents, excluding idempotent updates
    if response.status == "created":
        INCIDENTS_CREATED_TOTAL.labels(
            source="alertmanager",
            severity=incident.severity.value
            if hasattr(incident.severity, "value")
            else str(incident.severity),
        ).inc()
    return response
