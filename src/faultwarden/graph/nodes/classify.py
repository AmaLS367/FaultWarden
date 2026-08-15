"""Classification node: parses incoming alert and initializes investigation parameters."""

from typing import Any

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.graph.nodes.classify")


async def classify_incident_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Inspect alert metadata and classify initial severity and category."""
    incident_id = state.get("incident_id", "unknown")
    alert = state.get("alert", {})
    logger.info("node_classify_incident_start", incident_id=incident_id)

    # Deterministic placeholder classification
    common_labels = alert.get("commonLabels", {})
    alertname = common_labels.get("alertname", "UnknownAlert")
    service = common_labels.get("job", common_labels.get("service", "unknown-service"))
    severity = common_labels.get("severity", "MEDIUM").upper()

    logger.info(
        "node_classify_incident_completed",
        incident_id=incident_id,
        alertname=alertname,
        service=service,
        severity=severity,
    )

    return {
        "iteration_count": 1,
        "errors": [],
    }
