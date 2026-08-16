"""Additional telemetry collection node: executes targeted queries for missing evidence."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.loki.client import LokiClient
from faultwarden.integrations.prometheus.client import PrometheusClient
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType

logger = get_logger("faultwarden.graph.nodes.collect_additional")


# --- Additional Telemetry Collection ---
async def collect_additional_telemetry_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Execute targeted metric or log queries to resolve uncertainty from previous iterations."""
    incident_id = state.get("incident_id", "unknown")
    missing_queries = state.get("missing_evidence_queries", [])
    current_iteration = state.get("iteration_count", 1)
    next_iteration = current_iteration + 1

    logger.info(
        "collect_additional_telemetry_start",
        incident_id=incident_id,
        iteration=next_iteration,
        queries_count=len(missing_queries),
    )

    settings = get_settings()
    lookback = timedelta(minutes=settings.investigation.metrics_lookback_minutes)
    end_time = datetime.now(UTC)
    start_time = end_time - lookback

    prom_client = PrometheusClient(settings.prometheus)
    loki_client = LokiClient(settings.loki)
    new_evidence: list[EvidenceItem] = []

    for query_str in missing_queries[:3]:  # Cap at 3 targeted queries per iteration
        query_clean = query_str.strip()
        if not query_clean:
            continue

        if query_clean.startswith("{") or "log" in query_clean.lower():
            # Treat as Loki LogQL query
            try:
                log_entries = await loki_client.query_range(
                    query=query_clean, start=start_time, end=end_time, limit=20
                )
                if log_entries:
                    sample = log_entries[0]
                    new_evidence.append(
                        EvidenceItem(
                            id=str(uuid4()),
                            evidence_type=EvidenceType.LOG,
                            source="loki",
                            collected_at=datetime.now(UTC),
                            confidence=1.0,
                            relevance=0.9,
                            summary=f"Targeted log query '{query_clean}' returned {len(log_entries)} matching entries: {sample.message[:150]}",
                            data={"match_count": len(log_entries), "sample": sample.message},
                            query_reference=query_clean,
                        )
                    )
            except Exception as exc:
                logger.warning("targeted_loki_query_failed", query=query_clean, error=str(exc))
        else:
            # Treat as Prometheus PromQL query
            try:
                metrics = await prom_client.query_range(
                    expr=query_clean, start=start_time, end=end_time, step="15s"
                )
                for m in metrics:
                    latest_val = m.values[-1].value if m.values else 0.0
                    new_evidence.append(
                        EvidenceItem(
                            id=str(uuid4()),
                            evidence_type=EvidenceType.METRIC,
                            source="prometheus",
                            collected_at=datetime.now(UTC),
                            confidence=1.0,
                            relevance=0.9,
                            summary=f"Targeted PromQL query '{query_clean}' evaluated to {latest_val:.2f}",
                            data={"query": query_clean, "latest_value": latest_val},
                            query_reference=query_clean,
                        )
                    )
            except Exception as exc:
                logger.warning("targeted_promql_query_failed", query=query_clean, error=str(exc))

    return {
        "iteration_count": next_iteration,
        "evidence": new_evidence,
        "missing_evidence_queries": [],
    }
