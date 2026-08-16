"""Remediation action execution and validation nodes."""

import asyncio
from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import (
    get_remediation_executor_from_config,
    get_remediation_validator_from_config,
)
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    AllowedAction,
    ApprovalRequiredAction,
    RemediationValidationResult,
)

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
    if not result.success:
        logger.warning(
            "remediation_execution_failed",
            incident_id=incident_id,
            action_id=action.id,
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            error=result.error,
        )

    return {"remediation_result": result}


# --- Post-Remediation Validation Node ---
async def validate_remediation_node(
    state: IncidentInvestigationState, config: RunnableConfig | None = None
) -> dict[str, Any]:
    """Deterministically verify the remediation actually recovered the target, not just that the executor call succeeded.

    This is a separate, delayed verification pass — independent of the executor's own immediate
    post-condition check — so a remediation is never marked resolved on the strength of "the API
    call returned 200" alone. The LLM plays no role here: recovery criteria are deterministic
    (re-querying the target's own state), matching the milestone's requirement that validation
    "combine deterministic checks" rather than trust LLM reasoning for fundamental correctness.
    """
    incident_id = state.get("incident_id", "unknown")
    rem_result = state.get("remediation_result")
    policy_result = state.get("remediation_policy_result")

    if rem_result is None or not rem_result.success:
        # Nothing executed, or execution itself failed — no point checking recovery.
        return {"remediation_validation_passed": None}

    if not isinstance(policy_result, (AllowedAction, ApprovalRequiredAction)):
        raise ValueError(
            f"Routing invariant violation: validate_remediation_node reached without an executed action: {type(policy_result)}"
        )
    action = policy_result.action

    logger.info("remediation_validation_started", incident_id=incident_id, action_id=action.id)

    settings = get_settings()
    delay = settings.remediation.validation_delay_seconds
    if delay > 0:
        await asyncio.sleep(delay)

    validator = get_remediation_validator_from_config(config)
    val_result: RemediationValidationResult | None = None
    recovered: bool = False

    try:
        raw_val = await validator(action)
        if isinstance(raw_val, RemediationValidationResult):
            val_result = raw_val
            recovered = raw_val.passed
        elif isinstance(raw_val, bool):
            recovered = raw_val
        else:
            recovered = bool(raw_val)
    except Exception as exc:
        logger.warning(
            "remediation_validation_check_errored",
            incident_id=incident_id,
            action_id=action.id,
            error=str(exc),
        )
        recovered = False

    logger.info(
        "remediation_validation_completed",
        incident_id=incident_id,
        action_id=action.id,
        passed=recovered,
    )
    logger.info(
        "remediation_validation_succeeded" if recovered else "remediation_validation_failed",
        incident_id=incident_id,
        action_id=action.id,
    )

    return {
        "remediation_validation_passed": recovered,
        "remediation_validation_result": val_result,
    }
