"""Domain and application exception definitions."""

from typing import Any


# --- Base Exception ---
class FaultWardenError(Exception):
    """Base exception for all FaultWarden errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


# --- Domain Exceptions ---
class IncidentNotFoundError(FaultWardenError):
    """Raised when an incident ID does not exist."""

    def __init__(self, incident_id: str) -> None:
        super().__init__(
            f"Incident with ID '{incident_id}' was not found.", {"incident_id": incident_id}
        )
        self.incident_id = incident_id


class RemediationActionNotFoundError(FaultWardenError):
    """Raised when a remediation action ID does not exist."""

    def __init__(self, action_id: str) -> None:
        super().__init__(
            f"Remediation action with ID '{action_id}' was not found.", {"action_id": action_id}
        )
        self.action_id = action_id


class RemediationProposalNotFoundError(FaultWardenError):
    """Raised when a remediation proposal ID does not exist."""

    def __init__(self, proposal_id: str) -> None:
        super().__init__(
            f"Remediation proposal with ID '{proposal_id}' was not found.",
            {"proposal_id": proposal_id},
        )
        self.proposal_id = proposal_id


class InvalidAlertPayloadError(FaultWardenError):
    """Raised when an incoming alert payload fails validation or parsing."""

    def __init__(self, reason: str, payload_preview: str | None = None) -> None:
        super().__init__(f"Invalid alert payload: {reason}", {"payload_preview": payload_preview})


# --- Provider Exceptions ---
class ProviderError(FaultWardenError):
    """Raised when an external observability or LLM provider fails."""

    def __init__(self, provider_name: str, message: str, status_code: int | None = None) -> None:
        super().__init__(
            f"Provider '{provider_name}' error: {message}",
            {"provider": provider_name, "status_code": status_code},
        )
        self.provider_name = provider_name
        self.status_code = status_code


class PrometheusError(ProviderError):
    """Raised on Prometheus query failure."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__("prometheus", message, status_code)


class LokiError(ProviderError):
    """Raised on Loki log query failure."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__("loki", message, status_code)


class LLMError(ProviderError):
    """Raised on LLM provider failure."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__("llm", message, status_code)


class RemediationExecutionError(ProviderError):
    """Raised when a remediation executor fails to complete its bounded capability call."""

    def __init__(self, executor: str, message: str, status_code: int | None = None) -> None:
        super().__init__(f"executor:{executor}", message, status_code)


# --- Safety & Workflow Exceptions ---
class RemediationSafetyError(FaultWardenError):
    """Raised when a remediation violates the safety tier or policy."""

    def __init__(self, action: str, required_level: int, attempted_level: int) -> None:
        super().__init__(
            f"Remediation action '{action}' requires Safety Level {required_level}, but Level {attempted_level} was attempted.",
            {
                "action": action,
                "required_level": required_level,
                "attempted_level": attempted_level,
            },
        )


class RemediationNotAwaitingApprovalError(FaultWardenError):
    """Raised when attempting to approve or resume an incident that is not awaiting approval."""

    def __init__(self, incident_id: str, current_status: str | None = None) -> None:
        super().__init__(
            f"Incident '{incident_id}' is not in AWAITING_APPROVAL status (current: {current_status}).",
            {"incident_id": incident_id, "current_status": current_status},
        )
        self.incident_id = incident_id
        self.current_status = current_status


class RemediationApprovalStaleError(FaultWardenError):
    """Raised when an approval decision arrives after the configured approval_timeout_seconds window."""

    def __init__(self, action_id: str, pending_seconds: float, timeout_seconds: float) -> None:
        super().__init__(
            f"Remediation action '{action_id}' has been awaiting approval for "
            f"{pending_seconds:.0f}s, exceeding the {timeout_seconds:.0f}s timeout. "
            "Re-run the investigation to generate a fresh proposal.",
            {
                "action_id": action_id,
                "pending_seconds": pending_seconds,
                "timeout_seconds": timeout_seconds,
            },
        )
        self.action_id = action_id


class InvestigationWorkflowError(FaultWardenError):
    """Raised when the LangGraph investigation workflow fails during execution."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(
            f"Investigation graph error at stage '{stage}': {message}", {"stage": stage}
        )


class InvalidStateTransitionError(FaultWardenError):
    """Raised when an invalid entity lifecycle state transition is attempted."""

    def __init__(self, entity: str, current_status: str, target_status: str) -> None:
        super().__init__(
            f"Invalid {entity} state transition from '{current_status}' to '{target_status}'.",
            {
                "entity": entity,
                "current_status": current_status,
                "target_status": target_status,
            },
        )
        self.entity = entity
        self.current_status = current_status
        self.target_status = target_status


class RemediationExecutionClaimError(FaultWardenError):
    """Raised when an action cannot be claimed for execution (e.g. already executing or completed)."""

    def __init__(self, action_id: str, reason: str) -> None:
        super().__init__(
            f"Cannot claim remediation action '{action_id}' for execution: {reason}",
            {"action_id": action_id, "reason": reason},
        )
        self.action_id = action_id
        self.reason = reason


class ActiveJobConflictError(FaultWardenError):
    """Raised when an operation conflicts with an already pending or running investigation job."""

    def __init__(self, incident_id: str, job_id: str, job_status: str) -> None:
        super().__init__(
            f"An active investigation job '{job_id}' (status: '{job_status}') already exists for incident '{incident_id}'.",
            {
                "incident_id": incident_id,
                "job_id": job_id,
                "job_status": job_status,
            },
        )
        self.incident_id = incident_id
        self.job_id = job_id
        self.job_status = job_status
