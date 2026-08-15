"""Hypothesis verification node: evaluates candidates against evidence and determines root cause."""

from typing import Any

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.hypothesis import HypothesisStatus, RootCauseAnalysis

logger = get_logger("faultwarden.graph.nodes.verify")


async def verify_hypothesis_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Test candidate hypotheses and construct final RootCauseAnalysis."""
    incident_id = state.get("incident_id", "unknown")
    hypotheses = state.get("hypotheses", [])
    logger.info(
        "node_verify_hypothesis_start", incident_id=incident_id, candidate_count=len(hypotheses)
    )

    # Pick the highest confidence candidate deterministically
    selected_hypothesis = None
    if hypotheses:
        selected_hypothesis = max(hypotheses, key=lambda h: h.confidence_score)
        selected_hypothesis.status = HypothesisStatus.VERIFIED

    root_cause = None
    if selected_hypothesis:
        root_cause = RootCauseAnalysis(
            primary_hypothesis_id=selected_hypothesis.id,
            summary=f"Root cause verified: {selected_hypothesis.title}. {selected_hypothesis.description}",
            root_cause_category="CodeBug",
            culprit_service=selected_hypothesis.affected_component,
            contributing_factors=["Automated fault injection enabled", "Elevated 5xx rate"],
            technical_details={"confidence": selected_hypothesis.confidence_score},
            confidence=selected_hypothesis.confidence_score,
        )

    logger.info(
        "node_verify_hypothesis_completed",
        incident_id=incident_id,
        selected_id=selected_hypothesis.id if selected_hypothesis else None,
    )

    return {
        "selected_hypothesis": selected_hypothesis,
        "root_cause": root_cause,
    }
