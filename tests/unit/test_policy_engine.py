"""Unit tests for deterministic remediation policy registry and evaluator."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import TypeAdapter

from faultwarden.core.config import RemediationSettings
from faultwarden.core.policy import (
    POLICY_REGISTRY,
    evaluate_policy,
)
from faultwarden.schemas.remediation import (
    ActionType,
    AllowedAction,
    ApprovalRequiredAction,
    PolicyDecisionType,
    PolicyResult,
    RejectedAction,
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
    RestartRegisteredServiceExecutableAction,
    RestartRegisteredServiceParameters,
    RestartRegisteredServiceProposal,
)


@pytest.fixture
def default_remediation_settings() -> RemediationSettings:
    """Provide default RemediationSettings instance."""
    return RemediationSettings()


@pytest.fixture
def sample_reset_proposal() -> ResetDemoFailureProposal:
    """Provide a valid ResetDemoFailureProposal."""
    return ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id="inc-100",
        title="Reset Demo Error Injection",
        description="Clear simulated failure flag on demo service",
        expected_effect="200 OK responses restored",
        supporting_evidence_ids=["ev-1"],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )


@pytest.fixture
def sample_restart_proposal() -> RestartRegisteredServiceProposal:
    """Provide a valid RestartRegisteredServiceProposal."""
    return RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id="inc-101",
        title="Restart Demo Service",
        description="Perform controlled restart of demo-service container",
        expected_effect="Memory leaks and frozen event loop cleared",
        supporting_evidence_ids=["ev-2"],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )


def test_reset_demo_failure_allowed_under_default_settings(
    default_remediation_settings: RemediationSettings,
    sample_reset_proposal: ResetDemoFailureProposal,
) -> None:
    """Level 1 RESET_DEMO_FAILURE is auto-allowed under default max safety level 1."""
    result = evaluate_policy(sample_reset_proposal, settings=default_remediation_settings)

    assert isinstance(result, AllowedAction)
    assert result.decision == PolicyDecisionType.ALLOWED
    assert isinstance(result.action, ResetDemoFailureExecutableAction)
    assert result.action.proposal_id == sample_reset_proposal.id
    assert result.action.policy_level == RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC
    assert result.action.approval_required is False
    assert result.action.executor == "demo_service.reset_failure_mode"
    assert result.action.validated_parameters.service == "demo-service"


def test_restart_registered_service_requires_approval_under_default_settings(
    default_remediation_settings: RemediationSettings,
    sample_restart_proposal: RestartRegisteredServiceProposal,
) -> None:
    """Level 2 RESTART_REGISTERED_SERVICE requires human approval under default max safety level 1."""
    result = evaluate_policy(sample_restart_proposal, settings=default_remediation_settings)

    assert isinstance(result, ApprovalRequiredAction)
    assert result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert isinstance(result.action, RestartRegisteredServiceExecutableAction)
    assert result.action.proposal_id == sample_restart_proposal.id
    assert result.action.policy_level == RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
    assert result.action.approval_required is True
    assert result.action.executor == "registered_service.restart_simulated"
    assert result.action.validated_parameters.service_id == "demo-service"
    assert "LEVEL_2_HUMAN_APPROVAL_REQUIRED" in result.reason
    assert "exceeds auto-execute threshold" in result.reason


def test_llm_cannot_override_policy_risk_or_approval(
    default_remediation_settings: RemediationSettings,
) -> None:
    """Adversarial LLM claims a Level 2 action is Level 0 safe and requires no approval, but policy prevails."""
    deceptive_proposal = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id="inc-adversarial-1",
        title="Harmless Little Restart",
        description="Just a minor tweak, totally read-only!",
        expected_effect="Everything fixed magically",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_0_READ_ONLY,  # LLM lying: claims Level 0
        requires_approval=False,  # LLM lying: claims no approval needed
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )

    result = evaluate_policy(deceptive_proposal, settings=default_remediation_settings)

    # Architectural invariant: The policy engine is the sole authority
    assert isinstance(result, ApprovalRequiredAction)
    assert result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert result.action.policy_level == RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
    assert result.action.approval_required is True
    assert result.action.executor == "registered_service.restart_simulated"


def test_disabled_settings_rejects_any_proposal(
    sample_reset_proposal: ResetDemoFailureProposal,
) -> None:
    """When remediation is disabled in config, all proposals are rejected immediately."""
    disabled_settings = RemediationSettings(enabled=False)

    result = evaluate_policy(sample_reset_proposal, settings=disabled_settings)

    assert isinstance(result, RejectedAction)
    assert result.decision == PolicyDecisionType.REJECTED
    assert result.proposal_id == sample_reset_proposal.id
    assert result.action_type == ActionType.RESET_DEMO_FAILURE
    assert result.reason == "remediation pipeline disabled"


def test_auto_execute_max_safety_level_2_allows_level_2_actions(
    sample_restart_proposal: RestartRegisteredServiceProposal,
) -> None:
    """Raising auto_execute_max_safety_level to 2 permits Level 2 actions to auto-execute."""
    permissive_settings = RemediationSettings(auto_execute_max_safety_level=2)

    result = evaluate_policy(sample_restart_proposal, settings=permissive_settings)

    assert isinstance(result, AllowedAction)
    assert result.decision == PolicyDecisionType.ALLOWED
    assert isinstance(result.action, RestartRegisteredServiceExecutableAction)
    assert result.action.policy_level == RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
    assert result.action.approval_required is False


def test_auto_execute_max_safety_level_0_requires_approval_for_level_1(
    sample_reset_proposal: ResetDemoFailureProposal,
) -> None:
    """Lowering auto_execute_max_safety_level to 0 forces Level 1 actions to require approval."""
    strict_settings = RemediationSettings(auto_execute_max_safety_level=0)

    result = evaluate_policy(sample_reset_proposal, settings=strict_settings)

    assert isinstance(result, ApprovalRequiredAction)
    assert result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert result.action.policy_level == RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC
    assert result.action.approval_required is True


def test_adversarial_unauthorized_target_rejected_safely(
    default_remediation_settings: RemediationSettings,
) -> None:
    """Proposal targeting unauthorized infrastructure bypassing pydantic validation is rejected."""
    # Construct proposal bypassing standard Literal validation
    unauthorized_proposal = ResetDemoFailureProposal.model_construct(
        id="prop-bypass-1",
        incident_id="inc-bypass-1",
        title="Unauthorized Target Attack",
        description="Target production database directly",
        expected_effect="Disaster",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        action_type=ActionType.RESET_DEMO_FAILURE,
        parameters=ResetDemoFailureParameters.model_construct(service="production-db-cluster"),  # type: ignore[arg-type]
    )

    result = evaluate_policy(unauthorized_proposal, settings=default_remediation_settings)

    assert isinstance(result, RejectedAction)
    assert result.decision == PolicyDecisionType.REJECTED
    assert result.proposal_id == "prop-bypass-1"
    assert result.action_type == ActionType.RESET_DEMO_FAILURE
    assert "production-db-cluster" in result.reason
    assert "not in allowed targets" in result.reason


def test_unregistered_action_type_rejected_safely(
    default_remediation_settings: RemediationSettings,
) -> None:
    """Proposal with an unregistered action_type is safely rejected without raising KeyError."""
    unregistered_proposal = ResetDemoFailureProposal.model_construct(
        id="prop-unknown-1",
        incident_id="inc-unknown-1",
        title="Unknown Action Attack",
        description="Execute arbitrary payload",
        expected_effect="Unknown",
        supporting_evidence_ids=[],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        action_type="UNREGISTERED_ACTION_TYPE",  # type: ignore[arg-type]
        parameters={"service": "demo-service"},  # type: ignore[arg-type]
    )

    result = evaluate_policy(unregistered_proposal, settings=default_remediation_settings)

    assert isinstance(result, RejectedAction)
    assert result.decision == PolicyDecisionType.REJECTED
    assert result.proposal_id == "prop-unknown-1"
    assert "not registered in policy" in result.reason


def test_rejected_action_carries_audit_metadata(
    sample_reset_proposal: ResetDemoFailureProposal,
) -> None:
    """RejectedAction must have populated, non-empty audit fields."""
    disabled_settings = RemediationSettings(enabled=False)
    before = datetime.now(UTC)
    result = evaluate_policy(sample_reset_proposal, settings=disabled_settings)
    after = datetime.now(UTC)

    assert isinstance(result, RejectedAction)
    assert result.proposal_id == sample_reset_proposal.id
    assert result.action_type == ActionType.RESET_DEMO_FAILURE
    assert result.reason != ""
    assert isinstance(result.rejected_at, datetime)
    assert before <= result.rejected_at <= after


def test_policy_result_variants_serialization_roundtrip(
    default_remediation_settings: RemediationSettings,
    sample_reset_proposal: ResetDemoFailureProposal,
    sample_restart_proposal: RestartRegisteredServiceProposal,
) -> None:
    """All PolicyResult variants roundtrip cleanly through JSON serialization and TypeAdapter."""
    adapter: TypeAdapter[PolicyResult] = TypeAdapter(PolicyResult)

    # 1. AllowedAction roundtrip
    allowed_result = evaluate_policy(sample_reset_proposal, settings=default_remediation_settings)
    assert isinstance(allowed_result, AllowedAction)
    allowed_dump = allowed_result.model_dump(mode="json")
    allowed_parsed = adapter.validate_python(allowed_dump)
    assert isinstance(allowed_parsed, AllowedAction)
    assert allowed_parsed.decision == PolicyDecisionType.ALLOWED
    assert allowed_parsed.action.policy_level == RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC

    # 2. ApprovalRequiredAction roundtrip
    approval_result = evaluate_policy(
        sample_restart_proposal, settings=default_remediation_settings
    )
    assert isinstance(approval_result, ApprovalRequiredAction)
    approval_dump = approval_result.model_dump(mode="json")
    approval_parsed = adapter.validate_python(approval_dump)
    assert isinstance(approval_parsed, ApprovalRequiredAction)
    assert approval_parsed.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert approval_parsed.reason == approval_result.reason
    assert (
        approval_parsed.action.policy_level
        == RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
    )

    # 3. RejectedAction roundtrip
    disabled_settings = RemediationSettings(enabled=False)
    rejected_result = evaluate_policy(sample_reset_proposal, settings=disabled_settings)
    assert isinstance(rejected_result, RejectedAction)
    rejected_dump = rejected_result.model_dump(mode="json")
    rejected_parsed = adapter.validate_python(rejected_dump)
    assert isinstance(rejected_parsed, RejectedAction)
    assert rejected_parsed.decision == PolicyDecisionType.REJECTED
    assert rejected_parsed.proposal_id == sample_reset_proposal.id
    assert rejected_parsed.reason == "remediation pipeline disabled"


def test_policy_registry_completeness() -> None:
    """Every ActionType defined in the enum has a valid entry in POLICY_REGISTRY."""
    for action_type in ActionType:
        assert action_type in POLICY_REGISTRY
        entry = POLICY_REGISTRY[action_type]
        assert isinstance(entry.policy_level, RemediationSafetyLevel)
        assert isinstance(entry.executor, str)
        assert len(entry.executor) > 0
        assert len(entry.allowed_targets) > 0
