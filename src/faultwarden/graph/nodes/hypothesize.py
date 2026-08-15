"""Hypothesis generation node: produces candidate failure explanations."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.hypothesis import Hypothesis, HypothesisStatus

logger = get_logger("faultwarden.graph.nodes.hypothesize")


async def generate_hypotheses_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Generate candidate root cause hypotheses from accumulated evidence."""
    incident_id = state.get("incident_id", "unknown")
    evidence_list = state.get("evidence", [])
    logger.info(
        "node_generate_hypotheses_start", incident_id=incident_id, evidence_count=len(evidence_list)
    )

    now = datetime.now(UTC)
    evidence_ids = [e.id for e in evidence_list]

    # Deterministic placeholder hypotheses
    hypothesis_1 = Hypothesis(
        id=str(uuid4()),
        title="Application Fault Injection / Internal Bug",
        description="Demo service error-mode was enabled or unexpected exception triggered unhandled 500 responses.",
        affected_component="demo-service",
        confidence_score=0.85,
        status=HypothesisStatus.PROPOSED,
        supporting_evidence_ids=evidence_ids,
        created_at=now,
    )

    hypothesis_2 = Hypothesis(
        id=str(uuid4()),
        title="Upstream Dependency Outage",
        description="Downstream database or third-party payment gateway connection timeout.",
        affected_component="demo-service-dependency",
        confidence_score=0.35,
        status=HypothesisStatus.PROPOSED,
        supporting_evidence_ids=[],
        created_at=now,
    )

    logger.info("node_generate_hypotheses_completed", incident_id=incident_id, hypotheses_count=2)

    return {
        "hypotheses": [hypothesis_1, hypothesis_2],
    }
