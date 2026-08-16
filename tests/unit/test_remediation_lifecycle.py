"""Unit tests for remediation action lifecycle state machine (Issue 4).

Invariants:
- Valid transitions:
  - PROPOSED -> APPROVED, AWAITING_APPROVAL, REJECTED
  - AWAITING_APPROVAL -> APPROVED, REJECTED
  - APPROVED -> EXECUTING
  - EXECUTING -> SUCCEEDED, FAILED
- Invalid transitions:
  - SUCCEEDED -> EXECUTING (illegal)
  - FAILED -> EXECUTING (illegal)
  - REJECTED -> APPROVED (illegal)
  - AWAITING_APPROVAL -> SUCCEEDED (skipping approval/execution is illegal)
- Invalid transitions raise InvalidStateTransitionError.
"""

from uuid import uuid4

import pytest

from faultwarden.core.exceptions import InvalidStateTransitionError
from faultwarden.db.models.remediation import RemediationActionModel
from faultwarden.schemas.remediation import ActionType, PolicyDecisionType, RemediationStatus
from faultwarden.services.remediation_audit_service import (
    transition_action_status,
)


def _make_action_model(status: RemediationStatus) -> RemediationActionModel:
    return RemediationActionModel(
        id=uuid4(),
        proposal_id=uuid4(),
        incident_id=uuid4(),
        decision=PolicyDecisionType.ALLOWED,
        action_type=ActionType.RESET_DEMO_FAILURE,
        status=status,
    )


@pytest.mark.parametrize(
    ("initial_status", "target_status"),
    [
        (RemediationStatus.PROPOSED, RemediationStatus.APPROVED),
        (RemediationStatus.PROPOSED, RemediationStatus.AWAITING_APPROVAL),
        (RemediationStatus.PROPOSED, RemediationStatus.REJECTED),
        (RemediationStatus.AWAITING_APPROVAL, RemediationStatus.APPROVED),
        (RemediationStatus.AWAITING_APPROVAL, RemediationStatus.REJECTED),
        (RemediationStatus.APPROVED, RemediationStatus.EXECUTING),
        (RemediationStatus.EXECUTING, RemediationStatus.SUCCEEDED),
        (RemediationStatus.EXECUTING, RemediationStatus.FAILED),
    ],
)
def test_valid_state_transitions(
    initial_status: RemediationStatus, target_status: RemediationStatus
) -> None:
    """Allowed transitions succeed and update entity status."""
    action = _make_action_model(initial_status)
    transition_action_status(action, target_status)
    assert action.status == target_status


@pytest.mark.parametrize(
    ("initial_status", "invalid_target_status"),
    [
        (RemediationStatus.SUCCEEDED, RemediationStatus.EXECUTING),
        (RemediationStatus.SUCCEEDED, RemediationStatus.APPROVED),
        (RemediationStatus.FAILED, RemediationStatus.EXECUTING),
        (RemediationStatus.FAILED, RemediationStatus.APPROVED),
        (RemediationStatus.REJECTED, RemediationStatus.APPROVED),
        (RemediationStatus.REJECTED, RemediationStatus.EXECUTING),
        (RemediationStatus.AWAITING_APPROVAL, RemediationStatus.SUCCEEDED),
        (RemediationStatus.AWAITING_APPROVAL, RemediationStatus.EXECUTING),
        (RemediationStatus.PROPOSED, RemediationStatus.SUCCEEDED),
    ],
)
def test_invalid_state_transitions_raise_error(
    initial_status: RemediationStatus, invalid_target_status: RemediationStatus
) -> None:
    """Forbidden transitions raise InvalidStateTransitionError."""
    action = _make_action_model(initial_status)
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        transition_action_status(action, invalid_target_status)

    assert exc_info.value.current_status == initial_status.value
    assert exc_info.value.target_status == invalid_target_status.value


def test_transition_to_same_status_is_noop() -> None:
    """Transitioning to the exact same status is a no-op and does not raise."""
    action = _make_action_model(RemediationStatus.APPROVED)
    transition_action_status(action, RemediationStatus.APPROVED)
    assert action.status == RemediationStatus.APPROVED
