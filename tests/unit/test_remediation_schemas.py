"""Unit tests for typed remediation domain models, discriminated unions, and validation boundaries."""

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from faultwarden.schemas.remediation import (
    ActionType,
    RemediationActionCandidate,
    RemediationExecutionStatus,
    RemediationProposal,
    RemediationResult,
    RemediationSafetyLevel,
    ResetDemoFailureProposal,
    RestartRegisteredServiceProposal,
    parse_remediation_proposal,
)


def test_parse_valid_reset_demo_failure_candidate() -> None:
    """A valid RESET_DEMO_FAILURE candidate parses into ResetDemoFailureProposal via parse_remediation_proposal."""
    candidate = RemediationActionCandidate(
        name="Reset Fault Injection State",
        target_service="demo-service",
        safety_level=1,
        action_type="RESET_DEMO_FAILURE",
        parameters={"service": "demo-service"},
        description="Reset error injection flag via POST /debug/error-mode/false",
    )

    proposal = parse_remediation_proposal(
        candidate,
        incident_id="inc-test-1",
        supporting_evidence_ids=["ev-1", "ev-2"],
        expected_effect="Restores 200 OK responses.",
    )

    assert isinstance(proposal, ResetDemoFailureProposal)
    assert proposal.action_type == ActionType.RESET_DEMO_FAILURE
    assert proposal.incident_id == "inc-test-1"
    assert proposal.title == "Reset Fault Injection State"
    assert proposal.description == "Reset error injection flag via POST /debug/error-mode/false"
    assert proposal.expected_effect == "Restores 200 OK responses."
    assert proposal.supporting_evidence_ids == ["ev-1", "ev-2"]
    assert proposal.proposed_risk == RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC
    assert proposal.requires_approval is True
    assert proposal.parameters.service == "demo-service"


def test_parse_valid_restart_registered_service_candidate() -> None:
    """A valid RESTART_REGISTERED_SERVICE candidate parses into RestartRegisteredServiceProposal."""
    candidate = RemediationActionCandidate(
        name="Restart Demo Service",
        target_service="demo-service",
        safety_level=2,
        action_type="RESTART_REGISTERED_SERVICE",
        parameters={"service_id": "demo-service"},
        description="Simulate service restart",
    )

    proposal = parse_remediation_proposal(
        candidate,
        incident_id="inc-test-2",
        supporting_evidence_ids=["ev-3"],
        expected_effect="Recycles service process.",
    )

    assert isinstance(proposal, RestartRegisteredServiceProposal)
    assert proposal.action_type == ActionType.RESTART_REGISTERED_SERVICE
    assert proposal.incident_id == "inc-test-2"
    assert proposal.title == "Restart Demo Service"
    assert proposal.proposed_risk == RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED
    assert proposal.requires_approval is True
    assert proposal.parameters.service_id == "demo-service"


@pytest.mark.parametrize(
    "invalid_action_type",
    [
        "execute_shell",
        "restart_service",
        "scale_db_pool",
        "disable_error_mode",
        "arbitrary_command",
    ],
)
def test_unknown_action_type_is_rejected(invalid_action_type: str) -> None:
    """Unknown or legacy action types must raise ValidationError/ValueError, never silently coerce."""
    candidate = RemediationActionCandidate(
        name="Execute Forbidden Action",
        target_service="demo-service",
        safety_level=2,
        action_type=invalid_action_type,
        parameters={},
        description="Attempt to execute unlisted action",
    )

    with pytest.raises((ValidationError, ValueError)):
        parse_remediation_proposal(
            candidate,
            incident_id="inc-test-3",
            supporting_evidence_ids=[],
        )


def test_malformed_parameters_wrong_literal_rejected() -> None:
    """Parameters with invalid target service names outside the Literal are rejected."""
    candidate = RemediationActionCandidate(
        name="Reset Other Service",
        target_service="prod-db",
        safety_level=1,
        action_type="RESET_DEMO_FAILURE",
        parameters={"service": "prod-db"},
        description="Attempt to target unauthorized service",
    )

    with pytest.raises(ValidationError):
        parse_remediation_proposal(
            candidate,
            incident_id="inc-test-4",
            supporting_evidence_ids=[],
        )


def test_malformed_parameters_extra_keys_rejected() -> None:
    """Extra unexpected parameters must be rejected due to extra='forbid'."""
    candidate = RemediationActionCandidate(
        name="Reset with Extra Payload",
        target_service="demo-service",
        safety_level=1,
        action_type="RESET_DEMO_FAILURE",
        parameters={"service": "demo-service", "shell_command": "rm -rf /"},
        description="Attempt injection via extra kwargs",
    )

    with pytest.raises(ValidationError):
        parse_remediation_proposal(
            candidate,
            incident_id="inc-test-5",
            supporting_evidence_ids=[],
        )


def test_remediation_result_roundtrip() -> None:
    """RemediationResult serializes and deserializes accurately."""
    now = datetime.now(UTC)
    result = RemediationResult(
        action_id="act-12345",
        status=RemediationExecutionStatus.SUCCEEDED,
        started_at=now,
        completed_at=now,
        success=True,
        summary="Service reset completed successfully.",
        error=None,
        before_state={"error_mode": True},
        after_state={"error_mode": False},
    )

    dumped = result.model_dump(mode="json")
    validated = RemediationResult.model_validate(dumped)

    assert validated.action_id == "act-12345"
    assert validated.status == RemediationExecutionStatus.SUCCEEDED
    assert validated.success is True
    assert validated.summary == "Service reset completed successfully."
    assert validated.before_state == {"error_mode": True}
    assert validated.after_state == {"error_mode": False}


def test_type_adapter_discriminates_variants_from_plain_dict() -> None:
    """TypeAdapter(RemediationProposal) correctly validates and discriminates both variants from plain dicts."""
    adapter: TypeAdapter[RemediationProposal] = TypeAdapter(RemediationProposal)

    reset_dict = {
        "id": "prop-1",
        "incident_id": "inc-1",
        "title": "Reset Failure Mode",
        "description": "Reset error injection",
        "expected_effect": "Recovery",
        "supporting_evidence_ids": ["ev-1"],
        "proposed_risk": 1,
        "requires_approval": True,
        "action_type": "RESET_DEMO_FAILURE",
        "parameters": {"service": "demo-service"},
    }
    obj1 = adapter.validate_python(reset_dict)
    assert isinstance(obj1, ResetDemoFailureProposal)
    assert obj1.action_type == ActionType.RESET_DEMO_FAILURE
    assert obj1.parameters.service == "demo-service"

    restart_dict = {
        "id": "prop-2",
        "incident_id": "inc-2",
        "title": "Restart Service",
        "description": "Restart demo container",
        "expected_effect": "Fresh start",
        "supporting_evidence_ids": [],
        "proposed_risk": 2,
        "requires_approval": True,
        "action_type": "RESTART_REGISTERED_SERVICE",
        "parameters": {"service_id": "demo-service"},
    }
    obj2 = adapter.validate_python(restart_dict)
    assert isinstance(obj2, RestartRegisteredServiceProposal)
    assert obj2.action_type == ActionType.RESTART_REGISTERED_SERVICE
    assert obj2.parameters.service_id == "demo-service"
