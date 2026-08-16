"""Evidence correlation node: synthesizes and cross-references multi-source telemetry."""

from typing import Any

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.graph.nodes.correlate")


# --- Evidence Correlation ---
async def correlate_evidence_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Summarize accumulated metrics, logs, and alert evidence by type into a correlation summary.

    Does not reorder or return the `evidence` list itself: it uses an additive reducer
    (each collection node appends to it), so returning a re-sorted copy here would duplicate
    every prior item rather than reorder them.
    """
    incident_id = state.get("incident_id", "unknown")
    evidence_list = state.get("evidence", [])

    logger.info(
        "evidence_correlation_started",
        incident_id=incident_id,
        evidence_count=len(evidence_list),
    )

    metric_count = sum(1 for e in evidence_list if e.evidence_type == "METRIC")
    log_count = sum(1 for e in evidence_list if e.evidence_type == "LOG")
    alert_count = sum(1 for e in evidence_list if e.evidence_type == "ALERT")

    correlation_summary = (
        f"Correlated {len(evidence_list)} evidence items: "
        f"{alert_count} alert(s), {metric_count} metric sample(s), {log_count} log pattern(s)."
    )

    logger.info(
        "evidence_correlation_completed",
        incident_id=incident_id,
        total_evidence=len(evidence_list),
        summary=correlation_summary,
    )

    return {
        "summary": correlation_summary,
    }
