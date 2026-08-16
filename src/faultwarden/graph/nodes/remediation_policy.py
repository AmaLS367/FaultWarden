"""Deterministic remediation policy evaluation node."""

from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.core.policy import evaluate_policy
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import ActionType, AllowedAction, PolicyResult, RejectedAction

logger = get_logger("faultwarden.graph.nodes.remediation_policy")


def _extract_proposal_id_and_action_type(policy_result: PolicyResult) -> tuple[str, ActionType]:
    """Extract (proposal_id, action_type) from any PolicyResult variant."""
    if isinstance(policy_result, RejectedAction):
        return policy_result.proposal_id, policy_result.action_type
    return policy_result.action.proposal_id, policy_result.action.action_type


def _enforce_remediation_limits(
    policy_result: PolicyResult,
    *,
    prior_attempt_count: int,
    prior_auto_execution_count: int,
    max_attempts: int,
    max_auto_executions: int,
) -> PolicyResult:
    """Deterministically stop automation once configured attempt/auto-execution ceilings are hit.

    These limits come from Settings (never the LLM — see AGENTS.md) and are enforced here rather
    than inside evaluate_policy() so the core policy engine stays focused on per-proposal
    classification; this is a separate, incident-history-aware gate layered on top of it.
    """
    if prior_attempt_count >= max_attempts:
        proposal_id, action_type = _extract_proposal_id_and_action_type(policy_result)
        return RejectedAction(
            proposal_id=proposal_id,
            action_type=action_type,
            reason=(
                f"Maximum remediation attempts ({max_attempts}) reached for this incident; "
                "automation stopped, manual intervention required."
            ),
        )
    if (
        isinstance(policy_result, AllowedAction)
        and prior_auto_execution_count >= max_auto_executions
    ):
        return RejectedAction(
            proposal_id=policy_result.action.proposal_id,
            action_type=policy_result.action.action_type,
            reason=(
                f"Maximum auto-executed remediations ({max_auto_executions}) reached for this "
                "incident; automation stopped, manual intervention required."
            ),
        )
    return policy_result


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

    policy_result = _enforce_remediation_limits(
        policy_result,
        prior_attempt_count=state.get("remediation_prior_attempt_count", 0),
        prior_auto_execution_count=state.get("remediation_prior_auto_execution_count", 0),
        max_attempts=settings.remediation.max_remediation_attempts_per_incident,
        max_auto_executions=settings.remediation.max_auto_remediations_per_incident,
    )

    decision_value = (
        policy_result.decision.value
        if hasattr(policy_result.decision, "value")
        else str(policy_result.decision)
    )
    logger.info(
        "remediation_policy_evaluated",
        incident_id=incident_id,
        primary_proposal_id=primary_proposal.id,
        decision=decision_value,
    )
    if isinstance(policy_result, RejectedAction):
        logger.info(
            "remediation_rejected_by_policy",
            incident_id=incident_id,
            proposal_id=primary_proposal.id,
            reason=policy_result.reason,
        )
    elif isinstance(policy_result, AllowedAction):
        logger.info(
            "remediation_auto_approved",
            incident_id=incident_id,
            action_id=policy_result.action.id,
            action_type=policy_result.action.action_type,
        )

    return {"remediation_policy_result": policy_result}
