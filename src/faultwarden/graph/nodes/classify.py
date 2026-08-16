"""Classification node: parses incoming alert and initializes investigation parameters."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import resolve_service_from_state
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.classification import IncidentCategory, IncidentClassification
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType

logger = get_logger("faultwarden.graph.nodes.classify")


# --- Classification Logic ---
async def classify_incident_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Inspect alert metadata, classify incident category, and emit initial alert evidence."""
    incident_id = state.get("incident_id", "unknown")
    alert = state.get("alert", {})
    common_labels = alert.get("commonLabels", {})
    common_annotations = alert.get("commonAnnotations", {})

    alert_name = common_labels.get("alertname", "UnknownAlert")
    service_name = resolve_service_from_state(state, default="unknown-service")
    severity = common_labels.get("severity", "MEDIUM").upper()
    description = common_annotations.get("description", common_annotations.get("summary", ""))

    logger.info(
        "investigation_started",
        incident_id=incident_id,
        alertname=alert_name,
        service=service_name,
        severity=severity,
    )

    # - Categorization Heuristics
    combined_text = f"{alert_name} {description} {service_name}".lower()

    if any(
        kw in combined_text
        for kw in ["pool", "db", "database", "timeout", "upstream", "downstream"]
    ):
        category = IncidentCategory.DEPENDENCY_FAILURE
        reasoning = "Alert metadata indicates database, connection pool, or dependency failure."
        suggested_queries = [
            f'sum(rate(http_requests_total{{status=~"5..", job="{service_name}"}}[1m]))',
            f'sum(rate(http_requests_total{{job="{service_name}"}}[1m]))',
        ]
        suggested_logs = ["error", "timeout", "pool", "connection", "exception"]
    elif any(kw in combined_text for kw in ["5xx", "error", "failed", "500", "502", "503", "504"]):
        category = IncidentCategory.HTTP_ERRORS
        reasoning = "Alert metadata indicates elevated HTTP 5xx server error responses."
        suggested_queries = [
            f'sum(rate(http_requests_total{{status=~"5..", job="{service_name}"}}[1m]))',
            f'sum(rate(http_requests_total{{job="{service_name}"}}[1m]))',
        ]
        suggested_logs = ["error", "exception", "failed"]
    elif any(kw in combined_text for kw in ["latency", "duration", "slow", "p95", "p99"]):
        category = IncidentCategory.LATENCY
        reasoning = "Alert metadata indicates latency degradation."
        suggested_queries = [
            f'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{{job="{service_name}"}}[1m])) by (le))',
            f'sum(rate(http_requests_total{{job="{service_name}"}}[1m]))',
        ]
        suggested_logs = ["timeout", "slow", "warning"]
    elif any(kw in combined_text for kw in ["memory", "cpu", "disk", "oom", "exhaustion", "quota"]):
        category = IncidentCategory.RESOURCE_EXHAUSTION
        reasoning = "Alert metadata indicates host or container resource exhaustion."
        suggested_queries = [
            f'container_memory_usage_bytes{{job="{service_name}"}}',
        ]
        suggested_logs = ["oom", "killed", "exhausted", "error"]
    else:
        category = IncidentCategory.UNKNOWN
        reasoning = "Unclassified alert symptoms; fallback to standard error and request metrics."
        suggested_queries = [
            f'sum(rate(http_requests_total{{job="{service_name}"}}[1m]))',
        ]
        suggested_logs = ["error"]

    classification = IncidentClassification(
        category=category,
        confidence=0.90,
        reasoning=reasoning,
        suggested_queries=suggested_queries,
        suggested_log_filters=suggested_logs,
    )

    # - Initial Evidence Item from Alert
    now = datetime.now(UTC)
    alert_evidence = EvidenceItem(
        id=str(uuid4()),
        evidence_type=EvidenceType.ALERT,
        source="alertmanager",
        collected_at=now,
        confidence=1.0,
        relevance=1.0,
        summary=f"Alertmanager notification [{severity}]: {alert_name} in {service_name}. {description}".strip(),
        data=alert,
        query_reference=None,
    )

    logger.info(
        "incident_classified",
        incident_id=incident_id,
        category=category.value,
        suggested_queries_count=len(suggested_queries),
    )

    return {
        "classification": classification,
        "evidence": [alert_evidence],
        "iteration_count": 1,
        "investigation_status": "INVESTIGATING",
        "missing_evidence_queries": [],
    }
