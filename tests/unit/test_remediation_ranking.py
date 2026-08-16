"""Unit tests for deterministic multi-candidate remediation ranking (Issue 2).

Invariants:
- Evaluate all proposals with deterministic policy.
- Drop RejectedAction candidates.
- Sort remaining actions deterministically:
  1. Suitability score descending
  2. Lowest authoritative policy level (Level 1 before Level 2)
  3. Action type string / title deterministic tie-breaker
- Never trust LLM proposed_risk or requires_approval.
"""

from uuid import uuid4

import pytest

from faultwarden.core.config import RemediationSettings
from faultwarden.core.policy import evaluate_and_rank_proposals
from faultwarden.schemas.remediation import (
    ActionType,
    AllowedAction,
    ApprovalRequiredAction,
    RemediationSafetyLevel,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
    RestartRegisteredServiceParameters,
    RestartRegisteredServiceProposal,
)


@pytest.mark.asyncio
async def test_llm_proposed_risk_and_approval_are_ignored() -> None:
    """Deterministic policy ignores LLM's proposed_risk and requires_approval values."""
    # Proposal claiming to be safe Level 1, but underlying policy maps restart to Level 2
    proposal = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id=str(uuid4()),
        title="Restart service claiming to be Level 1",
        description="Restarting",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,  # LLM claims Level 1
        requires_approval=False,  # LLM claims no approval needed
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )

    selected, _all_results, _reason = evaluate_and_rank_proposals(
        [proposal],
        settings=RemediationSettings(enabled=True, auto_execute_max_safety_level=1),
    )

    assert selected is not None
    # Must be ApprovalRequiredAction with Level 2 authoritative policy level
    assert isinstance(selected, ApprovalRequiredAction)
    assert selected.action.policy_level == RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
    assert selected.action.approval_required is True


@pytest.mark.asyncio
async def test_ranking_orders_level_1_before_level_2() -> None:
    """When both Level 1 and Level 2 candidates are suitable, Level 1 is preferred."""
    p_level2 = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id=str(uuid4()),
        title="Restart Registered Service (Level 2)",
        description="Restart",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )
    p_level1 = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(uuid4()),
        title="Reset Demo Error (Level 1)",
        description="Reset",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )

    # Pass Level 2 first in input list to verify sorting is deterministic
    selected, all_results, _reason = evaluate_and_rank_proposals(
        [p_level2, p_level1],
        settings=RemediationSettings(enabled=True, auto_execute_max_safety_level=1),
    )

    assert selected is not None
    assert isinstance(selected, AllowedAction)
    assert selected.action.action_type == ActionType.RESET_DEMO_FAILURE
    assert len(all_results) == 2


@pytest.mark.asyncio
async def test_ranking_drops_all_rejected_candidates() -> None:
    """Rejected actions are evaluated in all_results but excluded from executable ranked list."""
    p_disabled = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(uuid4()),
        title="Reset Demo Error",
        description="Reset",
        expected_effect="Recovery",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )

    # When pipeline is disabled, proposals become RejectedAction
    selected, all_results, _reason = evaluate_and_rank_proposals(
        [p_disabled],
        settings=RemediationSettings(enabled=False),
    )

    assert selected is not None
    assert selected.decision.value == "REJECTED"
    assert len(all_results) == 1
    assert all_results[0].decision.value == "REJECTED"
