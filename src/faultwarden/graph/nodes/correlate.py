"""Evidence correlation node: synthesizes and cross-references multi-source telemetry."""

from typing import Any

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.graph.nodes.correlate")


# --- Evidence Correlation ---
async def correlate_evidence_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Sort and correlate metrics, logs, and alert evidence into an aligned investigation timeline."""
    incident_id = state.get("incident_id", "unknown")
    evidence_list = state.get("evidence", [])

    logger.info(
        "evidence_correlation_started",
        incident_id=incident_id,
        evidence_count=len(evidence_list),
    )

    # Sort evidence items by relevance descending, then collection time
    sorted_evidence = sorted(
        evidence_list,
        key=lambda item: (item.relevance, item.collected_at),
        reverse=True,
    )

    # Summarize correlated findings
    metric_count = sum(1 for e in sorted_evidence if e.evidence_type == "METRIC")
    log_count = sum(1 for e in sorted_evidence if e.evidence_type == "LOG")
    alert_count = sum(1 for e in sorted_evidence if e.evidence_type == "ALERT")

    correlation_summary = (
        f"Correlated {len(sorted_evidence)} evidence items: "
        f"{alert_count} alert(s), {metric_count} metric sample(s), {log_count} log pattern(s)."
    )

    logger.info(
        "evidence_correlation_completed",
        incident_id=incident_id,
        total_evidence=len(sorted_evidence),
        summary=correlation_summary,
    )

    return {
        "summary": correlation_summary,
    }
