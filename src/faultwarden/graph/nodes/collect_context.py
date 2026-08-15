"""Context collection node: gathers metrics, logs, and deployment events."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.evidence import (
    DeploymentEvent,
    EvidenceItem,
    EvidenceType,
    LogEntry,
    MetricData,
    MetricDataPoint,
)

logger = get_logger("faultwarden.graph.nodes.collect_context")


async def collect_context_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Collect telemetry context from configured observability providers."""
    incident_id = state.get("incident_id", "unknown")
    alert = state.get("alert", {})
    common_labels = alert.get("commonLabels", {})
    service_name = common_labels.get("job", common_labels.get("service", "demo-service"))

    logger.info("node_collect_context_start", incident_id=incident_id, target_service=service_name)

    now = datetime.now(UTC)

    # Deterministic placeholder telemetry data
    sample_metrics = [
        MetricData(
            query=f'rate(http_requests_total{{status=~"5..", service="{service_name}"}}[5m])',
            labels={"service": service_name, "status": "500"},
            values=[MetricDataPoint(timestamp=now, value=12.5)],
            summary=f"Elevated 5xx error rate detected for service {service_name}",
        )
    ]

    sample_logs = [
        LogEntry(
            timestamp=now,
            level="ERROR",
            message=f"HTTP 500 Internal Server Error in {service_name} /api/checkout",
            labels={"service": service_name, "level": "ERROR"},
        )
    ]

    sample_deployments = [
        DeploymentEvent(
            service_name=service_name,
            version_tag="v1.4.2",
            deployed_at=now,
            commit_sha="a1b2c3d",
            author="sre-team",
            description="Recent release deployed 15 minutes ago",
        )
    ]

    evidence_item = EvidenceItem(
        id=str(uuid4()),
        evidence_type=EvidenceType.METRIC,
        source="prometheus",
        collected_at=now,
        confidence=1.0,
        data={"query": sample_metrics[0].query, "rate": 12.5},
        summary="High 5xx error rate observed in Prometheus",
    )

    logger.info("node_collect_context_completed", incident_id=incident_id, evidence_count=1)

    return {
        "metrics": sample_metrics,
        "logs": sample_logs,
        "recent_changes": sample_deployments,
        "evidence": [evidence_item],
    }
