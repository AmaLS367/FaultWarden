"""Unit tests for deterministic remediation eligibility gate (Issue 1).

Invariants:
- Never auto-execute without verified root cause.
- Confidence must meet or exceed min_root_cause_confidence (0.75).
- Supporting telemetry evidence must be present.
- Ineligible state allows advisory recommendations, blocks automated execution and resolution.
"""

from uuid import uuid4

import pytest

from faultwarden.core.policy import check_remediation_eligibility
from faultwarden.graph.nodes.remediation_policy import evaluate_remediation_policy_node
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType
from faultwarden.schemas.hypothesis import Hypothesis, HypothesisStatus, RootCauseAnalysis
from faultwarden.schemas.remediation import (
    RemediationEligibilityReason,
    RemediationSafetyLevel,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
)


def _make_proposal() -> ResetDemoFailureProposal:
    return ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id=str(uuid4()),
        title="Reset Demo Error Mode",
        description="Reset failure mode",
        expected_effect="Recovery",
        supporting_evidence_ids=["ev-1"],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )


@pytest.mark.asyncio
async def test_eligibility_fails_when_no_root_cause() -> None:
    """Eligibility check fails when root_cause is None."""
    result = check_remediation_eligibility(
        root_cause=None,
        selected_hypothesis=None,
        evidence=[],
        iteration_count=1,
        max_iterations=3,
        min_confidence=0.75,
    )
    assert not result.eligible
    assert result.reason == RemediationEligibilityReason.NO_ROOT_CAUSE
    assert result.evaluated_at is not None


@pytest.mark.asyncio
async def test_eligibility_fails_when_investigation_exhausted() -> None:
    """Eligibility check returns INVESTIGATION_EXHAUSTED when iteration_count >= max_iterations without root cause."""
    result = check_remediation_eligibility(
        root_cause=None,
        selected_hypothesis=None,
        evidence=[],
        iteration_count=3,
        max_iterations=3,
        min_confidence=0.75,
    )
    assert not result.eligible
    assert result.reason == RemediationEligibilityReason.INVESTIGATION_EXHAUSTED


@pytest.mark.asyncio
async def test_eligibility_fails_when_selected_hypothesis_not_verified() -> None:
    """Eligibility check fails when selected hypothesis is INCONCLUSIVE or REFUTED."""
    rc = RootCauseAnalysis(
        primary_hypothesis_id="hyp-1",
        summary="Pool exhausted",
        root_cause_category="RESOURCE_EXHAUSTION",
        culprit_service="demo-service",
        confidence=0.9,
        supporting_evidence_ids=["ev-1"],
    )
    hyp = Hypothesis(
        id="hyp-1",
        title="Unconfirmed hypothesis",
        description="Test",
        affected_component="demo-service",
        status=HypothesisStatus.INCONCLUSIVE,
        confidence_score=0.6,
    )
    result = check_remediation_eligibility(
        root_cause=rc,
        selected_hypothesis=hyp,
        evidence=[],
        min_confidence=0.75,
    )
    assert not result.eligible
    assert result.reason == RemediationEligibilityReason.ROOT_CAUSE_UNVERIFIED


@pytest.mark.asyncio
async def test_eligibility_fails_when_confidence_below_threshold() -> None:
    """Eligibility check fails when confidence < 0.75."""
    rc = RootCauseAnalysis(
        primary_hypothesis_id="hyp-1",
        summary="Low confidence root cause",
        root_cause_category="RESOURCE_EXHAUSTION",
        culprit_service="demo-service",
        confidence=0.65,
        supporting_evidence_ids=["ev-1"],
    )
    hyp = Hypothesis(
        id="hyp-1",
        title="Verified hypothesis",
        description="Test",
        affected_component="demo-service",
        status=HypothesisStatus.VERIFIED,
        confidence_score=0.8,
    )
    result = check_remediation_eligibility(
        root_cause=rc,
        selected_hypothesis=hyp,
        evidence=[],
        min_confidence=0.75,
    )
    assert not result.eligible
    assert result.reason == RemediationEligibilityReason.INSUFFICIENT_CONFIDENCE


@pytest.mark.asyncio
async def test_eligibility_fails_when_no_supporting_evidence() -> None:
    """Eligibility check fails when supporting evidence is completely absent."""
    rc = RootCauseAnalysis(
        primary_hypothesis_id="hyp-1",
        summary="Root cause without evidence",
        root_cause_category="RESOURCE_EXHAUSTION",
        culprit_service="demo-service",
        confidence=0.85,
        supporting_evidence_ids=[],
    )
    hyp = Hypothesis(
        id="hyp-1",
        title="Verified hypothesis",
        description="Test",
        affected_component="demo-service",
        status=HypothesisStatus.VERIFIED,
        confidence_score=0.85,
    )
    result = check_remediation_eligibility(
        root_cause=rc,
        selected_hypothesis=hyp,
        evidence=[],
        min_confidence=0.75,
    )
    assert not result.eligible
    assert result.reason == RemediationEligibilityReason.INSUFFICIENT_EVIDENCE


@pytest.mark.asyncio
async def test_eligibility_succeeds_with_verified_root_cause_and_evidence() -> None:
    """Eligibility check passes when root cause is verified, confidence >= 0.75, and evidence exists."""
    rc = RootCauseAnalysis(
        primary_hypothesis_id="hyp-1",
        summary="Pool exhausted",
        root_cause_category="RESOURCE_EXHAUSTION",
        culprit_service="demo-service",
        confidence=0.88,
        supporting_evidence_ids=["ev-1"],
    )
    hyp = Hypothesis(
        id="hyp-1",
        title="Verified hypothesis",
        description="Test",
        affected_component="demo-service",
        status=HypothesisStatus.VERIFIED,
        confidence_score=0.88,
    )
    ev = EvidenceItem(
        id="ev-1",
        source="prometheus",
        evidence_type=EvidenceType.METRIC,
        summary="5xx rate high",
        data={},
    )
    result = check_remediation_eligibility(
        root_cause=rc,
        selected_hypothesis=hyp,
        evidence=[ev],
        min_confidence=0.75,
    )
    assert result.eligible
    assert result.reason == RemediationEligibilityReason.ELIGIBLE


@pytest.mark.asyncio
async def test_policy_node_returns_none_result_when_ineligible() -> None:
    """evaluate_remediation_policy_node sets remediation_eligibility and None policy result when ineligible."""
    proposal = _make_proposal()
    state: IncidentInvestigationState = {
        "incident_id": "inc-ineligible-1",
        "incident_context": {"service": "demo-service"},
        "alert": {},
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [proposal],
        "iteration_count": 1,
        "missing_evidence_queries": [],
        "investigation_status": "INVESTIGATING",
        "summary": "",
        "errors": [],
    }

    result = await evaluate_remediation_policy_node(state, config=None)
    assert result["remediation_policy_result"] is None
    assert result["remediation_eligibility"] is not None
    assert not result["remediation_eligibility"].eligible
    assert result["remediation_eligibility"].reason == RemediationEligibilityReason.NO_ROOT_CAUSE
