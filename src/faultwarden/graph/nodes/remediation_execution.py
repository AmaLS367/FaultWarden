"""Remediation action execution and validation nodes."""

from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import get_remediation_executor_from_config
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import AllowedAction, ApprovalRequiredAction

logger = get_logger("faultwarden.graph.nodes.remediation_execution")


# --- Remediation Execution Node ---
async def execute_remediation_node(
    state: IncidentInvestigationState, config: RunnableConfig | None = None
) -> dict[str, Any]:
    """Execute the policy-approved RemediationAction via the injected bounded executor."""
    incident_id = state.get("incident_id", "unknown")
    policy_result = state.get("remediation_policy_result")

    if not isinstance(policy_result, (AllowedAction, ApprovalRequiredAction)):
        raise ValueError(
            f"Routing invariant violation: execute_remediation_node reached without executable action: {type(policy_result)}"
        )

    action = policy_result.action
    logger.info(
        "execute_remediation_start",
        incident_id=incident_id,
        action_id=action.id,
        action_type=action.action_type.value
        if hasattr(action.action_type, "value")
        else str(action.action_type),
        executor=action.executor,
    )

    executor = get_remediation_executor_from_config(config)
    result = await executor(action)

    logger.info(
        "execute_remediation_completed",
        incident_id=incident_id,
        action_id=action.id,
        success=result.success,
        status=result.status.value if hasattr(result.status, "value") else str(result.status),
    )

    return {"remediation_result": result}


# --- Post-Remediation Validation Node (Stub) ---
async def validate_remediation_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    """STUB for this task — real post-remediation validation lands in a later phase."""
    # TODO(phase-9-12): Replace this stub with real Prometheus/demo-service telemetry comparison.
    rem_result = state.get("remediation_result")
    passed = rem_result.success if rem_result is not None else None
    return {"remediation_validation_passed": passed}
