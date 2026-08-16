"""Deterministic policy registry and evaluation engine for remediation actions."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from faultwarden.core.config import RemediationSettings
from faultwarden.schemas.remediation import (
    ActionType,
    AllowedAction,
    ApprovalRequiredAction,
    PolicyDecisionType,
    PolicyResult,
    RejectedAction,
    RemediationAction,
    RemediationProposal,
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    RestartRegisteredServiceExecutableAction,
    RestartRegisteredServiceParameters,
)


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


POLICY_REGISTRY: dict[ActionType, PolicyRegistryEntry] = {
    ActionType.RESET_DEMO_FAILURE: PolicyRegistryEntry(
        policy_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        executor="demo_service.reset_failure_mode",
        allowed_targets=frozenset({"demo-service"}),
    ),
    ActionType.RESTART_REGISTERED_SERVICE: PolicyRegistryEntry(
        policy_level=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        executor="registered_service.restart_simulated",
        allowed_targets=frozenset({"demo-service"}),
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
    cleaned = "".join(ch for ch in str(target) if ch.isprintable())[:100]
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


# --- Policy Evaluator ---
def evaluate_policy(
    proposal: RemediationProposal,
    *,
    settings: RemediationSettings,
) -> PolicyResult:
    """Evaluate a remediation proposal against deterministic policy rules and configuration.

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
