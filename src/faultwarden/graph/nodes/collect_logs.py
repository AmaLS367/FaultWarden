"""Logs collection node: queries Grafana Loki for application and system logs."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.loki.client import LokiClient
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType, LogEntry

logger = get_logger("faultwarden.graph.nodes.collect_logs")


# --- Logs Collection ---
async def collect_initial_logs_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Fetch recent log records from Loki around the incident occurrence window."""
    incident_id = state.get("incident_id", "unknown")
    alert = state.get("alert", {})
    common_labels = alert.get("commonLabels", {})
    service_name = common_labels.get("job", common_labels.get("service", "demo-service"))

    settings = get_settings()
    lookback = timedelta(minutes=settings.investigation.logs_lookback_minutes)
    end_time = datetime.now(UTC)
    start_time = end_time - lookback

    client = LokiClient(settings.loki)
    if not await client.check_health():
        logger.info("loki_not_accessible_skipping_logs", service=service_name)
        return {
            "logs": [],
            "evidence": [],
        }

    collected_logs: list[LogEntry] = []
    collected_evidence: list[EvidenceItem] = []

    try:
        logs = await client.get_service_logs(
            service_name=service_name,
            start=start_time,
            end=end_time,
            limit=settings.investigation.logs_limit,
        )
        collected_logs.extend(logs)

        # Aggregate and highlight notable error logs as discrete EvidenceItems
        error_logs = [entry for entry in logs if entry.level in ("ERROR", "FATAL", "CRITICAL")]
        sample_errors = error_logs[:10]  # Limit to 10 distinct error samples

        for entry in sample_errors:
            collected_evidence.append(
                EvidenceItem(
                    id=str(uuid4()),
                    evidence_type=EvidenceType.LOG,
                    source="loki",
                    collected_at=datetime.now(UTC),
                    confidence=1.0,
                    relevance=1.0,
                    summary=f"Log [{entry.level}] from {service_name}: {entry.message[:250]}",
                    data={
                        "log_message": entry.message,
                        "timestamp": entry.timestamp.isoformat(),
                        "labels": entry.labels,
                    },
                    query_reference=f'{{service="{service_name}"}}',
                )
            )

        if not error_logs and logs:
            # If no explicit errors, add a summary of recent logs
            collected_evidence.append(
                EvidenceItem(
                    id=str(uuid4()),
                    evidence_type=EvidenceType.LOG,
                    source="loki",
                    collected_at=datetime.now(UTC),
                    confidence=0.8,
                    relevance=0.6,
                    summary=f"Retrieved {len(logs)} log entries from '{service_name}' with no explicit ERROR level.",
                    data={"total_count": len(logs)},
                    query_reference=f'{{service="{service_name}"}}',
                )
            )
    except Exception as exc:
        logger.warning("loki_logs_query_failed", service=service_name, error=str(exc))

    logger.info(
        "logs_collected",
        incident_id=incident_id,
        service=service_name,
        logs_count=len(collected_logs),
        evidence_count=len(collected_evidence),
    )

    return {
        "logs": collected_logs,
        "evidence": collected_evidence,
    }
