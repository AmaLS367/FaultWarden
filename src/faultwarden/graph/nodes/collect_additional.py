"""Additional telemetry collection node: executes targeted queries for missing evidence."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import get_logs_provider, get_metrics_provider
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType

logger = get_logger("faultwarden.graph.nodes.collect_additional")


# --- Additional Telemetry Collection ---
async def collect_additional_telemetry_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,
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

    prom_client = get_metrics_provider(config)
    loki_client = get_logs_provider(config)
    new_evidence: list[EvidenceItem] = []
    node_errors: list[str] = []

    for query_str in missing_queries[:3]:  # Cap at 3 targeted queries per iteration
        query_clean = query_str.strip()
        if not query_clean:
            continue

        if query_clean.startswith("{"):
            # LogQL queries always open with a stream selector; PromQL queries generated
            # elsewhere in this codebase always start with a function or metric name, so this
            # distinguishes the two without false-positiving on PromQL metrics/labels that merely
            # contain the substring "log" (e.g. catalog_requests_total, login_failures_total).
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
                node_errors.append(
                    f"collect_additional_telemetry: loki query '{query_clean}' failed: {exc}"
                )
        else:
            # Treat as Prometheus PromQL query
            try:
                metrics = await prom_client.query_range(
                    expr=query_clean, start=start_time, end=end_time, step="15s"
                )
                if metrics:
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
                else:
                    new_evidence.append(
                        EvidenceItem(
                            id=str(uuid4()),
                            evidence_type=EvidenceType.METRIC,
                            source="prometheus",
                            collected_at=datetime.now(UTC),
                            confidence=0.9,
                            relevance=0.7,
                            summary=f"Targeted PromQL query '{query_clean}' returned no metric data (0 series active).",
                            data={"query": query_clean, "series_count": 0},
                            query_reference=query_clean,
                        )
                    )
            except Exception as exc:
                logger.warning("targeted_promql_query_failed", query=query_clean, error=str(exc))
                node_errors.append(
                    f"collect_additional_telemetry: promql query '{query_clean}' failed: {exc}"
                )

    return {
        "iteration_count": next_iteration,
        "evidence": new_evidence,
        "missing_evidence_queries": [],
        "errors": node_errors,
    }
