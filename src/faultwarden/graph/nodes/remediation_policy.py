"""Deterministic remediation policy evaluation node with eligibility gate and multi-candidate ranking."""

from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.core.policy import (
    check_remediation_eligibility,
    evaluate_and_rank_proposals,
)
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    ActionType,
    AllowedAction,
    PolicyResult,
    RejectedAction,
)

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
    """Check eligibility, evaluate all candidate proposals against policy, and select safest suitable action."""
    incident_id = state.get("incident_id", "unknown")
    proposals = state.get("remediation_proposals", [])
    root_cause = state.get("root_cause")
    selected_hypothesis = state.get("selected_hypothesis")
    evidence_list = state.get("evidence", [])
    iteration_count = state.get("iteration_count", 1)

    settings = get_settings()

    logger.info(
        "evaluate_remediation_policy_start",
        incident_id=incident_id,
        proposals_count=len(proposals),
    )

    # 1. Deterministic Root-Cause Eligibility Gate (Issue 1)
    eligibility = check_remediation_eligibility(
        root_cause=root_cause,
        selected_hypothesis=selected_hypothesis,
        evidence=evidence_list,
        iteration_count=iteration_count,
        max_iterations=settings.investigation.max_iterations,
        min_confidence=settings.remediation.min_root_cause_confidence,
    )

    if not eligibility.eligible:
        logger.info(
            "remediation_ineligible",
            incident_id=incident_id,
            reason=eligibility.reason.value,
            details=eligibility.details,
        )
        return {
            "remediation_eligibility": eligibility,
            "remediation_policy_result": None,
            "remediation_all_policy_results": [],
            "remediation_selection_reason": eligibility.details,
        }

    if not proposals:
        logger.info("remediation_policy_no_proposals", incident_id=incident_id)
        return {
            "remediation_eligibility": eligibility,
            "remediation_policy_result": None,
            "remediation_all_policy_results": [],
            "remediation_selection_reason": "No proposals generated.",
        }

    # 2. Evaluate all proposals and rank using trusted deterministic rules (Issue 2)
    selected_policy_result, all_policy_results, selection_reason = evaluate_and_rank_proposals(
        proposals=proposals,
        root_cause=root_cause,
        classification=state.get("classification"),
        settings=settings.remediation,
    )

    if selected_policy_result is not None and not isinstance(
        selected_policy_result, RejectedAction
    ):
        # 3. Enforce attempt and auto-execution limits
        selected_policy_result = _enforce_remediation_limits(
            selected_policy_result,
            prior_attempt_count=state.get("remediation_prior_attempt_count", 0),
            prior_auto_execution_count=state.get("remediation_prior_auto_execution_count", 0),
            max_attempts=settings.remediation.max_remediation_attempts_per_incident,
            max_auto_executions=settings.remediation.max_auto_remediations_per_incident,
        )

    decision_value = "NONE"
    if selected_policy_result is not None:
        decision_value = selected_policy_result.decision.value

    logger.info(
        "remediation_policy_evaluated",
        incident_id=incident_id,
        decision=decision_value,
        selection_reason=selection_reason,
    )

    return {
        "remediation_eligibility": eligibility,
        "remediation_policy_result": selected_policy_result,
        "remediation_all_policy_results": all_policy_results,
        "remediation_selection_reason": selection_reason,
    }
