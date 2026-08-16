"""Human-in-the-loop approval pause node for Level-2 remediations."""

from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.types import interrupt

from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    ApprovalContext,
    ApprovalDecision,
    ApprovalRequiredAction,
)

logger = get_logger("faultwarden.graph.nodes.remediation_approval")


# --- Approval Node ---
async def await_remediation_approval_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    """Pause the graph on a Level-2 approval-required decision using langgraph.types.interrupt()."""
    incident_id = state.get("incident_id", "unknown")
    policy_result = state.get("remediation_policy_result")

    # Invariant: this node must only be reached when policy_result is ApprovalRequiredAction
    if not isinstance(policy_result, ApprovalRequiredAction):
        raise ValueError(
            f"Routing invariant violation: await_remediation_approval_node reached with invalid policy result: {type(policy_result)}"
        )

    action = policy_result.action
    root_cause = state.get("root_cause")
    incident_ctx = state.get("incident_context", {})

    # Look up proposal details for context
    proposals = state.get("remediation_proposals", [])
    matching_proposal = next((p for p in proposals if p.id == action.proposal_id), None)
    expected_effect = (
        matching_proposal.expected_effect
        if matching_proposal
        else "Restores normal service operations."
    )
    supporting_evidence_ids = (
        list(matching_proposal.supporting_evidence_ids)
        if matching_proposal
        else (list(root_cause.supporting_evidence_ids) if root_cause else [])
    )

    action_params: dict[str, Any] = (
        action.validated_parameters.model_dump(mode="json")
        if hasattr(action.validated_parameters, "model_dump")
        else dict(action.validated_parameters)
    )

    approval_ctx = ApprovalContext(
        incident_id=incident_id,
        incident_title=incident_ctx.get("title", ""),
        root_cause_summary=root_cause.summary if root_cause else None,
        confidence=root_cause.confidence if root_cause else None,
        action_type=action.action_type,
        action_parameters=action_params,
        policy_level=action.policy_level,
        expected_effect=expected_effect,
        supporting_evidence_ids=supporting_evidence_ids,
        reason_approval_required=policy_result.reason,
    )

    logger.info(
        "remediation_approval_interrupting",
        incident_id=incident_id,
        action_id=action.id,
        action_type=action.action_type.value
        if hasattr(action.action_type, "value")
        else str(action.action_type),
        policy_level=action.policy_level.value
        if hasattr(action.policy_level, "value")
        else int(action.policy_level),
    )

    # Pause execution until resumed with an operator Command(resume=...)
    resume_val = interrupt(approval_ctx.model_dump(mode="json"))

    logger.info(
        "remediation_approval_resumed",
        incident_id=incident_id,
        resume_val_type=type(resume_val).__name__,
    )

    # Defensive parsing of resume value
    decision_value: str
    try:
        if isinstance(resume_val, dict) and "decision" in resume_val:
            decision_enum = ApprovalDecision(str(resume_val["decision"]).upper())
            decision_value = decision_enum.value
        elif isinstance(resume_val, str):
            decision_enum = ApprovalDecision(resume_val.upper())
            decision_value = decision_enum.value
        else:
            logger.warning(
                "remediation_approval_unrecognized_resume_value",
                incident_id=incident_id,
                received=resume_val,
            )
            decision_value = ApprovalDecision.REJECT.value
    except (ValueError, KeyError) as parse_err:
        logger.warning(
            "remediation_approval_resume_parse_error",
            incident_id=incident_id,
            error=str(parse_err),
            received=resume_val,
        )
        decision_value = ApprovalDecision.REJECT.value

    return {"remediation_approval_decision": decision_value}
