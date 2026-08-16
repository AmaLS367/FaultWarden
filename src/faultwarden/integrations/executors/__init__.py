"""Bounded remediation executors and type-safe dispatcher."""

from faultwarden.core.exceptions import RemediationExecutionError
from faultwarden.integrations.executors.demo_service import DemoServiceExecutor
from faultwarden.integrations.executors.registered_service import RegisteredServiceExecutor
from faultwarden.schemas.remediation import (
    RemediationAction,
    RemediationResult,
    ResetDemoFailureExecutableAction,
    RestartRegisteredServiceExecutableAction,
)

__all__ = [
    "DemoServiceExecutor",
    "RegisteredServiceExecutor",
    "execute_remediation_action",
]


# --- Type-Safe Action Dispatcher ---
async def execute_remediation_action(action: RemediationAction) -> RemediationResult:
    """Type-safe dispatch to the correct bounded executor based on the action's discriminated variant."""
    if isinstance(action, ResetDemoFailureExecutableAction):
        return await DemoServiceExecutor().reset_failure_mode(action)
    if isinstance(action, RestartRegisteredServiceExecutableAction):
        return await RegisteredServiceExecutor().restart(action)
    # exhaustiveness: if mypy strict + a new ActionType variant is ever added without updating
    # this function, this line should be unreachable and typed as such
    raise RemediationExecutionError(
        "dispatcher", f"No executor registered for action type: {action.action_type}"
    )
