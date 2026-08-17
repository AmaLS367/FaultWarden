"""TypedDict state definition for LangGraph incident investigation workflow."""

import operator
from typing import Annotated, Any, TypedDict

from faultwarden.schemas.change import ChangeCorrelation, OperationalChange
from faultwarden.schemas.classification import IncidentClassification
from faultwarden.schemas.evidence import (
    EvidenceItem,
    LogEntry,
    MetricData,
    TraceSpan,
)
from faultwarden.schemas.hypothesis import Hypothesis, RootCauseAnalysis
from faultwarden.schemas.memory import SimilarIncidentMemory
from faultwarden.schemas.remediation import (
    PolicyResult,
    RemediationEligibilityResult,
    RemediationProposal,
    RemediationResult,
    RemediationValidationResult,
)


def _replace_hypotheses(_old: list[Hypothesis], new: list[Hypothesis]) -> list[Hypothesis]:
    """Each re-hypothesize pass regenerates a fresh candidate set from cumulative evidence, so replace rather than accumulate."""
    return new


def _replace_proposals(
    _old: list[RemediationProposal], new: list[RemediationProposal]
) -> list[RemediationProposal]:
    """Replace proposals on re-proposal to prevent duplicate accumulation."""
    return new


def _replace_changes(
    _old: list[OperationalChange], new: list[OperationalChange]
) -> list[OperationalChange]:
    """Replace recent changes list when collected to prevent duplicate accumulation."""
    return new


class IncidentInvestigationState(TypedDict, total=False):
    """Complete typed state passed across all LangGraph investigation nodes."""

    # --- Primary Identifiers & Context ---
    incident_id: str
    incident_context: dict[str, Any]
    alert: dict[str, Any]
    classification: IncidentClassification | None

    # --- Historical Context (Incident Memory — context only, never evidence) ---
    similar_incidents: list[SimilarIncidentMemory]

    # --- Change Intelligence (context & candidate causal factors — never raw evidence) ---
    recent_changes: Annotated[list[OperationalChange], _replace_changes]
    change_correlations: list[ChangeCorrelation]
    candidate_causal_changes: list[OperationalChange]
    selected_causal_change: OperationalChange | None

    # --- Telemetry & Collected Evidence (appended across steps) ---
    evidence: Annotated[list[EvidenceItem], operator.add]
    metrics: Annotated[list[MetricData], operator.add]
    logs: Annotated[list[LogEntry], operator.add]
    traces: Annotated[list[TraceSpan], operator.add]

    # --- Reasoning & Hypotheses ---
    hypotheses: Annotated[list[Hypothesis], _replace_hypotheses]
    selected_hypothesis: Hypothesis | None
    root_cause: RootCauseAnalysis | None

    # --- Remediation Proposals & Eligibility ---
    remediation_proposals: Annotated[list[RemediationProposal], _replace_proposals]
    remediation_eligibility: RemediationEligibilityResult | None

    # --- Remediation Policy, Selection & Approval ---
    remediation_policy_result: PolicyResult | None
    remediation_all_policy_results: list[PolicyResult]
    remediation_selection_reason: str | None
    remediation_approval_decision: (
        str | None
    )  # ApprovalDecision value, set only if the approval node ran
    remediation_result: RemediationResult | None
    remediation_validation_result: RemediationValidationResult | None
    remediation_validation_passed: bool | None

    # --- Remediation Limits (populated by the service layer from prior-attempt history,
    # never by the LLM — see AGENTS.md: limits must not be model-controlled) ---
    remediation_prior_attempt_count: int
    remediation_prior_auto_execution_count: int

    # --- Iterative Loop Control & Missing Telemetry ---
    iteration_count: int
    missing_evidence_queries: list[str]
    investigation_status: str
    summary: str

    # --- Error Tracking ---
    errors: Annotated[list[str], operator.add]
