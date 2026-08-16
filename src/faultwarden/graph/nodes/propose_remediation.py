"""Remediation proposal node: suggests tier-classified remediation plans (read-only)."""

from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableConfig

from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import get_llm_provider_from_config
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    ActionType,
    RemediationProposal,
    RemediationProposalResponse,
    RemediationSafetyLevel,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
    RestartRegisteredServiceParameters,
    RestartRegisteredServiceProposal,
    parse_remediation_proposal,
)

logger = get_logger("faultwarden.graph.nodes.propose_remediation")


# --- Remediation Proposal Logic (Read-Only) ---
async def propose_remediation_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,
) -> dict[str, Any]:
    """Generate structured remediation proposals based on identified root cause (recommendations only)."""
    incident_id = state.get("incident_id", "unknown")
    root_cause = state.get("root_cause")
    selected_hyp = state.get("selected_hypothesis")

    logger.info("propose_remediation_start", incident_id=incident_id)

    target_service = (
        root_cause.culprit_service
        if root_cause
        else (selected_hyp.affected_component if selected_hyp else "demo-service")
    )
    cause_summary = (
        root_cause.summary
        if root_cause
        else (selected_hyp.description if selected_hyp else "Unconfirmed failure mode")
    )

    # Derive supporting evidence IDs from root cause, selected hypothesis, or general evidence
    evidence_ids: list[str] = []
    if root_cause and root_cause.supporting_evidence_ids:
        evidence_ids = list(root_cause.supporting_evidence_ids)
    elif selected_hyp and selected_hyp.supporting_evidence_ids:
        evidence_ids = list(selected_hyp.supporting_evidence_ids)
    else:
        evidence_ids = [e.id for e in state.get("evidence", [])]

    prompt = (
        f"Generate a safe, structured remediation plan for the following incident root cause:\n\n"
        f"Target Service: {target_service}\n"
        f"Root Cause: {cause_summary}\n\n"
        "Guidelines:\n"
        "1. Propose 1 to 2 discrete actions matching supported action types: RESET_DEMO_FAILURE or RESTART_REGISTERED_SERVICE.\n"
        "2. Assign safety levels: 1 for safe non-destructive parameter resets, 2 for service restarts.\n"
        "3. This is for recommendations ONLY; do NOT execute any action."
    )

    llm = get_llm_provider_from_config(config)
    node_errors: list[str] = []
    proposals: list[RemediationProposal] = []

    try:
        response: RemediationProposalResponse = await llm.generate_structured(
            prompt=prompt,
            schema=RemediationProposalResponse,
            system_prompt="You are FaultWarden's Safe Remediation Advisor.",
        )

        for act in response.actions:
            try:
                proposal = parse_remediation_proposal(
                    act,
                    incident_id=incident_id,
                    supporting_evidence_ids=evidence_ids,
                    expected_effect=response.estimated_impact
                    or "Restores normal service operations.",
                    title=act.name,
                )
                proposals.append(proposal)
            except Exception as val_err:
                logger.warning(
                    "remediation_candidate_rejected",
                    action_type=act.action_type,
                    error=str(val_err),
                )
    except Exception as exc:
        logger.warning("llm_remediation_proposal_failed", error=str(exc))
        node_errors.append(
            f"propose_remediation: LLM proposal generation failed, using fallback: {exc}"
        )

    if not proposals:
        # Fallback deterministic actions as separate RemediationProposals (one per safety tier)
        proposals = [
            ResetDemoFailureProposal(
                id=str(uuid4()),
                incident_id=incident_id,
                title="Reset Fault Injection State",
                description="Reset debug error simulation mode via HTTP POST /debug/error-mode/false",
                expected_effect="Eliminates simulated 500 error faults on demo-service.",
                supporting_evidence_ids=evidence_ids,
                proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
                requires_approval=True,
                action_type=ActionType.RESET_DEMO_FAILURE,
                parameters=ResetDemoFailureParameters(service="demo-service"),
            ),
            RestartRegisteredServiceProposal(
                id=str(uuid4()),
                incident_id=incident_id,
                title="Simulate Service Restart",
                description="Trigger a simulated restart of the registered demo service container.",
                expected_effect="Simulated restart of the registered demo service",
                supporting_evidence_ids=evidence_ids,
                proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
                requires_approval=True,
                action_type=ActionType.RESTART_REGISTERED_SERVICE,
                parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
            ),
        ]

    logger.info(
        "remediation_proposals_generated",
        incident_id=incident_id,
        proposals_count=len(proposals),
    )

    return {
        "remediation_proposals": proposals,
        "errors": node_errors,
    }
