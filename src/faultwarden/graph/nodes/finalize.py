"""Finalize investigation node: compiles final summary and investigation status."""

from typing import Any

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.graph.nodes.finalize")


# --- Finalize Investigation ---
async def finalize_investigation_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Assemble the executive summary and set final investigation status."""
    incident_id = state.get("incident_id", "unknown")
    root_cause = state.get("root_cause")
    selected_hyp = state.get("selected_hypothesis")
    evidence_list = state.get("evidence", [])
    proposals = state.get("remediation_proposals", [])
    iterations = state.get("iteration_count", 1)

    if root_cause:
        status_str = "COMPLETED"
        summary = (
            f"Investigation completed after {iterations} iteration(s). "
            f"Root cause verified: {root_cause.summary} (confidence: {root_cause.confidence:.2f}). "
            f"Evaluated {len(evidence_list)} evidence item(s). "
            f"Generated {len(proposals)} remediation proposal(s)."
        )
    elif selected_hyp:
        status_str = "INCONCLUSIVE"
        summary = (
            f"Investigation reached maximum iterations ({iterations}) with unconfirmed root cause. "
            f"Leading hypothesis: {selected_hyp.title} (confidence: {selected_hyp.confidence_score:.2f}). "
            f"Evaluated {len(evidence_list)} evidence item(s)."
        )
    else:
        status_str = "FAILED"
        summary = f"Investigation concluded without finding viable hypotheses across {iterations} iteration(s)."

    logger.info(
        "investigation_completed",
        incident_id=incident_id,
        status=status_str,
        iterations=iterations,
        has_root_cause=root_cause is not None,
    )

    return {
        "investigation_status": status_str,
        "summary": summary,
    }
