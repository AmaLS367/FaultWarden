"""Deterministic remediation policy evaluation node."""

from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.core.policy import evaluate_policy
from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.graph.nodes.remediation_policy")


# --- Policy Evaluation Node ---
async def evaluate_remediation_policy_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    """Select the primary remediation proposal and evaluate it against deterministic policy. Pure — no I/O, no DB."""
    incident_id = state.get("incident_id", "unknown")
    proposals = state.get("remediation_proposals", [])

    logger.info(
        "evaluate_remediation_policy_start",
        incident_id=incident_id,
        proposals_count=len(proposals),
    )

    if not proposals:
        logger.info("remediation_policy_no_proposals", incident_id=incident_id)
        return {"remediation_policy_result": None}

    # Primary proposal selection: select the proposal with the highest proposed_risk
    # (ties broken by list order).
    # Rationale: this reflects real triage practice (address the most significant
    # concern first) and avoids the unscoped complexity of orchestrating simultaneous
    # multi-action approval/execution, which is explicitly out of scope for v0.3.
    # The remaining proposals stay in state["remediation_proposals"] as recommendations only.
    primary_proposal = max(
        proposals,
        key=lambda p: (
            int(p.proposed_risk.value)
            if hasattr(p.proposed_risk, "value")
            else int(p.proposed_risk)
        ),
    )

    settings = get_settings()
    policy_result = evaluate_policy(primary_proposal, settings=settings.remediation)

    logger.info(
        "remediation_policy_evaluated",
        incident_id=incident_id,
        primary_proposal_id=primary_proposal.id,
        decision=policy_result.decision.value
        if hasattr(policy_result.decision, "value")
        else str(policy_result.decision),
    )

    return {"remediation_policy_result": policy_result}
