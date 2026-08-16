"""Metrics collection node: queries Prometheus telemetry for the incident window."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import extract_service_name, get_metrics_provider
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType, MetricData

logger = get_logger("faultwarden.graph.nodes.collect_metrics")


# --- Metrics Collection ---
async def collect_initial_metrics_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,
) -> dict[str, Any]:
    """Gather time-series telemetry from Prometheus covering the incident window."""
    incident_id = state.get("incident_id", "unknown")
    alert = state.get("alert", {})
    common_labels = alert.get("commonLabels", {})
    service_name = extract_service_name(common_labels, default="demo-service")

    settings = get_settings()
    lookback = timedelta(minutes=settings.investigation.metrics_lookback_minutes)
    end_time = datetime.now(UTC)
    start_time = end_time - lookback

    client = get_metrics_provider(config)
    if not await client.check_health():
        logger.info("prometheus_not_accessible_skipping_metrics", service=service_name)
        return {
            "metrics": [],
            "evidence": [],
        }

    collected_metrics: list[MetricData] = []
    collected_evidence: list[EvidenceItem] = []
    node_errors: list[str] = []

    # - Standard Rate Queries
    try:
        err_metrics = await client.get_service_error_rate(
            service_name=service_name, start=start_time, end=end_time
        )
        collected_metrics.extend(err_metrics)

        for m in err_metrics:
            latest_val = m.values[-1].value if m.values else 0.0
            collected_evidence.append(
                EvidenceItem(
                    id=str(uuid4()),
                    evidence_type=EvidenceType.METRIC,
                    source="prometheus",
                    collected_at=datetime.now(UTC),
                    confidence=1.0,
                    relevance=1.0 if latest_val > 0 else 0.5,
                    summary=f"HTTP 5xx error rate for '{service_name}': {latest_val:.2f} req/s (query: {m.query})",
                    data={
                        "metric_query": m.query,
                        "labels": m.labels,
                        "points_count": len(m.values),
                        "latest_value": latest_val,
                    },
                    query_reference=m.query,
                )
            )
    except Exception as exc:
        logger.warning("metrics_error_rate_query_failed", service=service_name, error=str(exc))
        node_errors.append(f"collect_initial_metrics: error rate query failed: {exc}")

    try:
        req_metrics = await client.get_service_request_rate(
            service_name=service_name, start=start_time, end=end_time
        )
        collected_metrics.extend(req_metrics)

        for m in req_metrics:
            latest_val = m.values[-1].value if m.values else 0.0
            collected_evidence.append(
                EvidenceItem(
                    id=str(uuid4()),
                    evidence_type=EvidenceType.METRIC,
                    source="prometheus",
                    collected_at=datetime.now(UTC),
                    confidence=1.0,
                    relevance=0.8,
                    summary=f"Total request throughput for '{service_name}': {latest_val:.2f} req/s",
                    data={
                        "metric_query": m.query,
                        "labels": m.labels,
                        "points_count": len(m.values),
                        "latest_value": latest_val,
                    },
                    query_reference=m.query,
                )
            )
    except Exception as exc:
        logger.warning("metrics_request_rate_query_failed", service=service_name, error=str(exc))
        node_errors.append(f"collect_initial_metrics: request rate query failed: {exc}")

    logger.info(
        "metrics_collected",
        incident_id=incident_id,
        service=service_name,
        metrics_count=len(collected_metrics),
        evidence_count=len(collected_evidence),
    )

    return {
        "metrics": collected_metrics,
        "evidence": collected_evidence,
        "errors": node_errors,
    }
