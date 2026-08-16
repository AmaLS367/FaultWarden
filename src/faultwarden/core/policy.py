"""Deterministic policy registry, eligibility gate, and evaluation engine for remediation actions."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from faultwarden.core.config import RemediationSettings
from faultwarden.schemas.classification import IncidentClassification
from faultwarden.schemas.evidence import EvidenceItem
from faultwarden.schemas.hypothesis import Hypothesis, HypothesisStatus, RootCauseAnalysis
from faultwarden.schemas.remediation import (
    ActionType,
    AllowedAction,
    ApprovalRequiredAction,
    PolicyDecisionType,
    PolicyResult,
    RejectedAction,
    RemediationAction,
    RemediationEligibilityReason,
    RemediationEligibilityResult,
    RemediationProposal,
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    RestartRegisteredServiceExecutableAction,
    RestartRegisteredServiceParameters,
)


# --- Idempotency Classifications ---
class ActionIdempotency(StrEnum):
    """Side-effect idempotency classification governing executor retry and reconciliation behavior."""

    IDEMPOTENT = "IDEMPOTENT"
    NON_IDEMPOTENT = "NON_IDEMPOTENT"
    MANUAL_RECONCILIATION = "MANUAL_RECONCILIATION"


# --- Policy Registry ---
@dataclass(frozen=True)
class PolicyRegistryEntry:
    """Static metadata and safety constraints governing an executable action type."""

    policy_level: (
        RemediationSafetyLevel  # intrinsic risk of this action type — fixed, not configurable
    )
    executor: str  # capability identifier, e.g. "demo_service.reset_failure_mode"
    allowed_targets: frozenset[
        str
    ]  # defense-in-depth allowlist, independent of the Literal param type
    idempotency: ActionIdempotency = ActionIdempotency.IDEMPOTENT


POLICY_REGISTRY: dict[ActionType, PolicyRegistryEntry] = {
    ActionType.RESET_DEMO_FAILURE: PolicyRegistryEntry(
        policy_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        executor="demo_service.reset_failure_mode",
        allowed_targets=frozenset({"demo-service"}),
        idempotency=ActionIdempotency.IDEMPOTENT,
    ),
    ActionType.RESTART_REGISTERED_SERVICE: PolicyRegistryEntry(
        policy_level=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        executor="registered_service.restart_simulated",
        allowed_targets=frozenset({"demo-service"}),
        idempotency=ActionIdempotency.IDEMPOTENT,
    ),
}


# --- Target Extraction Helpers ---
def _extract_target(parameters: Any) -> str | None:
    """Extract target service identifier generically from action parameters."""
    if hasattr(parameters, "service"):
        target = parameters.service
        return str(target) if target is not None else None
    if hasattr(parameters, "service_id"):
        target = parameters.service_id
        return str(target) if target is not None else None
    if isinstance(parameters, dict):
        target = parameters.get("service") or parameters.get("service_id")
        return str(target) if target is not None else None
    return None


def _sanitize_target(target: str | None) -> str:
    """Sanitize target string to prevent log injection and unbounded error message lengths."""
    if target is None:
        return "<missing>"
    cleaned = "".join(ch for ch in target if ch.isprintable())[:100]
    return cleaned if cleaned else "<empty>"


def _make_rejected_action(
    *,
    proposal_id: str,
    action_type: Any,
    reason: str,
) -> RejectedAction:
    """Safely construct a RejectedAction even when action_type is an unvalidated string."""
    try:
        typed_action_type = (
            action_type if isinstance(action_type, ActionType) else ActionType(str(action_type))
        )
        return RejectedAction(
            proposal_id=proposal_id,
            action_type=typed_action_type,
            reason=reason,
        )
    except (ValueError, ValidationError):
        return RejectedAction.model_construct(
            decision=PolicyDecisionType.REJECTED,
            proposal_id=proposal_id,
            action_type=action_type,
            reason=reason,
            rejected_at=datetime.now(UTC),
        )


# --- Deterministic Remediation Eligibility Gate ---
def check_remediation_eligibility(
    *,
    root_cause: RootCauseAnalysis | None,
    selected_hypothesis: Hypothesis | None,
    evidence: list[EvidenceItem] | None = None,
    iteration_count: int = 1,
    max_iterations: int = 3,
    min_confidence: float = 0.75,
) -> RemediationEligibilityResult:
    """Determine deterministically whether an incident is eligible for automated remediation execution.

    Application code owns this gate; LLM reasoning cannot bypass or fabricate eligibility.
    When ineligible, proposals may still be generated and presented to operators as recommendations,
    but automatic policy execution is blocked and the incident is not falsely marked resolved.
    """
    if root_cause is None:
        if iteration_count >= max_iterations:
            return RemediationEligibilityResult(
                eligible=False,
                reason=RemediationEligibilityReason.INVESTIGATION_EXHAUSTED,
                details=(
                    f"Investigation reached maximum iterations ({max_iterations}) without "
                    "verifying a root cause. Automation is blocked; recommendations are advisory."
                ),
            )
        return RemediationEligibilityResult(
            eligible=False,
            reason=RemediationEligibilityReason.NO_ROOT_CAUSE,
            details="No root cause was identified during investigation.",
        )

    # Check hypothesis verification status if hypothesis is available
    if selected_hypothesis is not None and selected_hypothesis.status != HypothesisStatus.VERIFIED:
        return RemediationEligibilityResult(
            eligible=False,
            reason=RemediationEligibilityReason.ROOT_CAUSE_UNVERIFIED,
            details=(
                f"Selected hypothesis '{selected_hypothesis.title}' is in status "
                f"'{selected_hypothesis.status.value}', not VERIFIED."
            ),
        )

    # Check root cause confidence threshold
    if root_cause.confidence < min_confidence:
        return RemediationEligibilityResult(
            eligible=False,
            reason=RemediationEligibilityReason.INSUFFICIENT_CONFIDENCE,
            details=(
                f"Root cause confidence ({root_cause.confidence:.2f}) is below the required "
                f"remediation threshold ({min_confidence:.2f})."
            ),
        )

    # Check supporting evidence presence
    has_evidence_ids = bool(root_cause.supporting_evidence_ids)
    has_evidence_items = bool(evidence)
    if not (has_evidence_ids or has_evidence_items):
        return RemediationEligibilityResult(
            eligible=False,
            reason=RemediationEligibilityReason.INSUFFICIENT_EVIDENCE,
            details="Root cause lacks supporting telemetry evidence.",
        )

    return RemediationEligibilityResult(
        eligible=True,
        reason=RemediationEligibilityReason.ELIGIBLE,
        details="Root cause is verified with sufficient confidence and supporting evidence.",
    )


# --- Policy Evaluator ---
def evaluate_policy(
    proposal: RemediationProposal,
    *,
    settings: RemediationSettings,
) -> PolicyResult:
    """Evaluate a single remediation proposal against deterministic policy rules and configuration.

    This function is pure: it performs no I/O, does not call get_settings(), and derives
    all decisions from the provided proposal, static policy registry, and explicit settings.
    The LLM's suggested proposed_risk and requires_approval on the proposal are ignored for
    the decision.
    """
    # 1. Master kill-switch check
    if not settings.enabled:
        return _make_rejected_action(
            proposal_id=proposal.id,
            action_type=proposal.action_type,
            reason="remediation pipeline disabled",
        )

    # 2. Registry lookup (safe .get to guarantee totality without KeyError)
    entry = POLICY_REGISTRY.get(proposal.action_type)
    if entry is None:
        return _make_rejected_action(
            proposal_id=proposal.id,
            action_type=proposal.action_type,
            reason=f"Action type '{proposal.action_type}' is not registered in policy.",
        )

    # 3. Target allowlist check (defense-in-depth independent of schema typing)
    target = _extract_target(getattr(proposal, "parameters", None))
    if target not in entry.allowed_targets:
        safe_target = _sanitize_target(target)
        return _make_rejected_action(
            proposal_id=proposal.id,
            action_type=proposal.action_type,
            reason=(
                f"Target '{safe_target}' is not in allowed targets for action '{proposal.action_type}'."
            ),
        )

    # 4. Authoritative risk classification and approval requirement
    approval_required = entry.policy_level > settings.auto_execute_max_safety_level

    # Generate a stable execution identity key based on proposal identity
    idempotency_key = f"rem-exec-{proposal.id}"

    try:
        if proposal.action_type == ActionType.RESET_DEMO_FAILURE:
            params = (
                proposal.parameters
                if isinstance(proposal.parameters, ResetDemoFailureParameters)
                else ResetDemoFailureParameters.model_validate(proposal.parameters)
            )
            action: RemediationAction = ResetDemoFailureExecutableAction(
                id=str(uuid4()),
                proposal_id=proposal.id,
                policy_level=entry.policy_level,
                approval_required=approval_required,
                executor=entry.executor,
                validated_parameters=params,
                idempotency_key=idempotency_key,
            )
        elif proposal.action_type == ActionType.RESTART_REGISTERED_SERVICE:
            params_restart = (
                proposal.parameters
                if isinstance(proposal.parameters, RestartRegisteredServiceParameters)
                else RestartRegisteredServiceParameters.model_validate(proposal.parameters)
            )
            action = RestartRegisteredServiceExecutableAction(
                id=str(uuid4()),
                proposal_id=proposal.id,
                policy_level=entry.policy_level,
                approval_required=approval_required,
                executor=entry.executor,
                validated_parameters=params_restart,
                idempotency_key=idempotency_key,
            )
        else:
            return _make_rejected_action(
                proposal_id=proposal.id,
                action_type=proposal.action_type,
                reason=f"Unsupported action type: {proposal.action_type}",
            )
    except Exception as exc:
        return _make_rejected_action(
            proposal_id=proposal.id,
            action_type=proposal.action_type,
            reason=f"Parameter validation failed: {exc}",
        )

    # 5. Return authoritative decision
    if approval_required:
        return ApprovalRequiredAction(
            action=action,
            reason=(
                f"Safety level {entry.policy_level.name} (level {entry.policy_level.value}) "
                f"exceeds auto-execute threshold ({settings.auto_execute_max_safety_level})."
            ),
        )

    return AllowedAction(action=action)


# --- Deterministic Action Ranking & Selection ---
def _calculate_action_suitability(
    action_type: ActionType,
    *,
    root_cause: RootCauseAnalysis | None,
    classification: IncidentClassification | None,
) -> int:
    """Calculate deterministic capability suitability score (lower is more suitable).

    Scores:
    0: Direct match for specific fault injection / parameter error condition.
    1: Generic service recovery / restart action.
    2: Other supported actions.
    """
    cause_text = ""
    if root_cause is not None:
        cause_text = f"{root_cause.summary} {root_cause.root_cause_category}".lower()
    if classification is not None:
        cause_text = f"{cause_text} {classification.category.value}".lower()

    if not cause_text:
        return 0

    # If the root cause or category mentions error mode, simulated pool exhaustion, or parameter fault:
    is_fault_injection = any(
        keyword in cause_text
        for keyword in ("error-mode", "pool", "exhaust", "fault", "injection", "parameter", "debug")
    )

    if action_type == ActionType.RESET_DEMO_FAILURE:
        return 0 if is_fault_injection else 1
    if action_type == ActionType.RESTART_REGISTERED_SERVICE:
        return 1 if is_fault_injection else 0

    return 2


def evaluate_and_rank_proposals(
    proposals: list[RemediationProposal],
    *,
    settings: RemediationSettings,
    root_cause: RootCauseAnalysis | None = None,
    classification: IncidentClassification | None = None,
) -> tuple[PolicyResult | None, list[PolicyResult], str]:
    """Evaluate all candidate proposals against policy and deterministically rank non-rejected actions.

    Ranking rules (AGENTS.md invariant: LLM proposed_risk and requires_approval are IGNORED):
    1. Filter out all RejectedAction outcomes.
    2. Rank remaining by capability suitability to the verified root cause (lower suitability score wins).
    3. Rank by lowest authoritative policy level (Level 1 Safe Automatic preferred over Level 2 Approval Required).
    4. Stable tie-breaker: ActionType string order, then proposal ID.
    """
    if not proposals:
        return None, [], "No proposals provided."

    all_results: list[PolicyResult] = []
    candidates: list[tuple[RemediationProposal, AllowedAction | ApprovalRequiredAction]] = []

    for proposal in proposals:
        policy_res = evaluate_policy(proposal, settings=settings)
        all_results.append(policy_res)
        if isinstance(policy_res, (AllowedAction, ApprovalRequiredAction)):
            candidates.append((proposal, policy_res))

    if not candidates:
        first_rejection = all_results[0] if all_results else None
        return (
            first_rejection,
            all_results,
            "All proposed remediation candidates were rejected by deterministic policy.",
        )

    def _ranking_key(
        item: tuple[RemediationProposal, AllowedAction | ApprovalRequiredAction],
    ) -> tuple[int, int, str, str]:
        prop, res = item
        action = res.action
        suitability = _calculate_action_suitability(
            action.action_type,
            root_cause=root_cause,
            classification=classification,
        )
        policy_level_val = int(action.policy_level.value)
        action_type_str = action.action_type.value
        prop_id_str = prop.id
        return (suitability, policy_level_val, action_type_str, prop_id_str)

    # Sort candidates deterministically
    candidates.sort(key=_ranking_key)
    selected_proposal, selected_policy_result = candidates[0]

    reason = (
        f"Selected action '{selected_policy_result.action.action_type.value}' as safest "
        f"suitable candidate (authoritative level {selected_policy_result.action.policy_level.value}) "
        f"for proposal '{selected_proposal.title}'."
    )

    return selected_policy_result, all_results, reason
