"""Remediation proposal node: suggests tier-classified remediation plans (read-only)."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableConfig

from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import get_llm_provider_from_config
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    RemediationAction,
    RemediationProposal,
    RemediationProposalResponse,
    RemediationSafetyLevel,
    RemediationStatus,
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

    prompt = (
        f"Generate a safe, structured remediation plan for the following incident root cause:\n\n"
        f"Target Service: {target_service}\n"
        f"Root Cause: {cause_summary}\n\n"
        "Guidelines:\n"
        "1. Propose 1 to 3 discrete actions.\n"
        "2. Assign safety levels: 1 for safe non-destructive parameter resets, 2 for rollbacks/scaling.\n"
        "3. Include a concise rollback plan.\n"
        "4. This is for recommendations ONLY; do NOT execute any action."
    )

    llm = get_llm_provider_from_config(config)
    node_errors: list[str] = []
    actions: list[RemediationAction] = []
    proposal_title = f"Remediation Proposal for {target_service}"
    proposal_summary = f"Remediation actions proposed for root cause: {cause_summary}"
    est_impact = "Restores normal request throughput and reduces error rates."
    rollback_plan = "Revert applied parameter changes if degradation persists."

    try:
        response: RemediationProposalResponse = await llm.generate_structured(
            prompt=prompt,
            schema=RemediationProposalResponse,
            system_prompt="You are FaultWarden's Safe Remediation Advisor.",
        )
        proposal_title = response.title or proposal_title
        proposal_summary = response.summary or proposal_summary
        est_impact = response.estimated_impact or est_impact
        rollback_plan = response.rollback_plan or rollback_plan

        for act in response.actions:
            if act.safety_level == 0:
                level = RemediationSafetyLevel.LEVEL_0_READ_ONLY
            elif act.safety_level == 1:
                level = RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC
            else:
                level = RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
            actions.append(
                RemediationAction(
                    id=str(uuid4()),
                    name=act.name,
                    target_service=act.target_service or target_service,
                    safety_level=level,
                    action_type=act.action_type,
                    parameters=act.parameters,
                    description=act.description,
                )
            )
    except Exception as exc:
        logger.warning("llm_remediation_proposal_failed", error=str(exc))
        node_errors.append(
            f"propose_remediation: LLM proposal generation failed, using fallback: {exc}"
        )

    if not actions:
        # Fallback deterministic actions
        actions = [
            RemediationAction(
                id=str(uuid4()),
                name="Reset Fault Injection State",
                target_service=target_service,
                safety_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
                action_type="disable_error_mode",
                parameters={"enabled": False},
                description="Reset debug error simulation mode via HTTP POST /debug/error-mode/false",
            ),
            RemediationAction(
                id=str(uuid4()),
                name="Scale Connection Pool Capacity",
                target_service=target_service,
                safety_level=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
                action_type="scale_db_pool",
                parameters={"max_connections": 50},
                description="Increase connection pool size to mitigate concurrency bottlenecks",
            ),
        ]

    highest_level = max(
        (a.safety_level for a in actions),
        default=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
    )

    now = datetime.now(UTC)
    proposal = RemediationProposal(
        id=str(uuid4()),
        incident_id=incident_id,
        title=proposal_title,
        summary=proposal_summary,
        highest_safety_level=highest_level,
        requires_human_approval=True,  # Safety invariant: recommendations require operator approval
        status=RemediationStatus.PROPOSED,
        actions=actions,
        estimated_impact=est_impact,
        rollback_plan=rollback_plan,
        created_at=now,
    )

    logger.info(
        "remediation_proposal_generated",
        incident_id=incident_id,
        proposal_id=proposal.id,
        actions_count=len(actions),
        highest_safety_level=int(highest_level),
    )

    return {
        "remediation_proposals": [proposal],
        "errors": node_errors,
    }
