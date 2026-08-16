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


class InvestigationWorkflowError(FaultWardenError):
    """Raised when the LangGraph investigation workflow fails during execution."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(
            f"Investigation graph error at stage '{stage}': {message}", {"stage": stage}
        )
