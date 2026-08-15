"""Remediation proposal node: suggests tier-classified remediation plans."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    RemediationAction,
    RemediationProposal,
    RemediationSafetyLevel,
    RemediationStatus,
)

logger = get_logger("faultwarden.graph.nodes.propose_remediation")


async def propose_remediation_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Generate structured remediation proposals based on identified root cause."""
    incident_id = state.get("incident_id", "unknown")
    root_cause = state.get("root_cause")
    logger.info("node_propose_remediation_start", incident_id=incident_id)

    target_service = root_cause.culprit_service if root_cause else "demo-service"
    now = datetime.now(UTC)

    # Deterministic placeholder remediation proposals
    action_1 = RemediationAction(
        id=str(uuid4()),
        name="Disable Error Simulation Mode",
        target_service=target_service,
        safety_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        action_type="disable_error_mode",
        parameters={"enabled": False},
        description="Reset the debug error mode flag to false via HTTP POST /debug/error-mode/false",
    )

    action_2 = RemediationAction(
        id=str(uuid4()),
        name="Rollback Service to Previous Release",
        target_service=target_service,
        safety_level=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        action_type="rollback_deployment",
        parameters={"target_version": "v1.4.1"},
        description="Rollback the demo-service container deployment to v1.4.1",
    )

    proposal = RemediationProposal(
        id=str(uuid4()),
        incident_id=incident_id,
        title=f"Remediation Proposal for {target_service}",
        summary="Disable simulated fault injection mode or restart service instance.",
        highest_safety_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_human_approval=False,
        status=RemediationStatus.PROPOSED,
        actions=[action_1, action_2],
        estimated_impact="Restores 100% HTTP 200 OK responses within 5 seconds",
        rollback_plan="Re-enable error mode if testing requires it",
        created_at=now,
    )

    logger.info(
        "node_propose_remediation_completed", incident_id=incident_id, proposal_id=proposal.id
    )

    return {
        "remediation_proposals": [proposal],
    }
