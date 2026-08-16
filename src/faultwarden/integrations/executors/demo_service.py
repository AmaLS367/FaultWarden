"""Demo service remediation executor for simulated fault injection resets."""

import asyncio
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from faultwarden.core.config import RemediationSettings, get_settings
from faultwarden.core.exceptions import RemediationExecutionError
from faultwarden.core.logging import get_logger
from faultwarden.schemas.remediation import (
    DemoServiceErrorModeResponse,
    RemediationExecutionStatus,
    RemediationResult,
    ResetDemoFailureExecutableAction,
)

logger = get_logger("faultwarden.integrations.executors.demo_service")

# Transient transport errors eligible for bounded retries
_TRANSIENT_EXCEPTIONS = (httpx.ConnectError, httpx.TimeoutException)


# --- Demo Service Executor ---
class DemoServiceExecutor:
    """Bounded executor for resetting demo service failure injection mode."""

    def __init__(self, settings: RemediationSettings | None = None) -> None:
        self._settings = settings or get_settings().remediation
        # Target URL originates strictly from trusted configuration, never from action parameters
        self._base_url = self._settings.demo_service_url.rstrip("/")
        self._timeout = self._settings.execution_timeout_seconds
        self._max_retries = 2
        self._retry_delay = 0.5

    async def _get_client(self) -> httpx.AsyncClient:
        """Build an httpx client bound strictly to configured demo service base URL."""
        return httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)

    async def _request_with_retry(
        self,
        method: Literal["GET", "POST"],
        path: str,
    ) -> tuple[httpx.Response | None, Exception | None]:
        """Perform HTTP request with bounded retries on transient connection and timeout failures."""
        last_exc: Exception | None = None
        for attempt in range(1 + self._max_retries):
            try:
                async with await self._get_client() as client:
                    if method == "GET":
                        resp = await client.get(path)
                    else:
                        resp = await client.post(path)
                    return resp, None
            except _TRANSIENT_EXCEPTIONS as exc:
                last_exc = exc
                logger.warning(
                    "demo_service_request_transient_error",
                    method=method,
                    path=path,
                    attempt=attempt + 1,
                    max_attempts=1 + self._max_retries,
                    error=str(exc),
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(self._retry_delay)

        return None, last_exc

    async def reset_failure_mode(
        self, action: ResetDemoFailureExecutableAction
    ) -> RemediationResult:
        """Reset the demo service's simulated fault-injection state via its debug API.

        Error contract:
        - Programming-contract violations (wrong action type) raise RemediationExecutionError.
        - All external HTTP/I/O outcomes (success, non-2xx, parse errors, timeout/connection
          exhaustion) return a typed RemediationResult (SUCCEEDED, FAILED, TIMED_OUT)
          so the orchestration workflow can audit and persist the outcome.
        """
        # 1. Enforce programming contract before performing any I/O
        if not isinstance(action, ResetDemoFailureExecutableAction):
            raise RemediationExecutionError(
                "demo_service",
                f"Invalid action type for DemoServiceExecutor: {type(action).__name__}",
            )

        started_at = datetime.now(UTC)

        # 2. Inspect initial error mode (GET /debug/error-mode)
        get_resp, get_exc = await self._request_with_retry("GET", "/debug/error-mode")
        if get_resp is None:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.TIMED_OUT,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Demo service error-mode inspection timed out after bounded retries.",
                error=f"Connection or timeout error during GET /debug/error-mode: {get_exc}",
                before_state=None,
                after_state=None,
            )

        if get_resp.status_code != 200:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary=f"Failed to inspect demo service error mode (HTTP {get_resp.status_code}).",
                error=f"HTTP {get_resp.status_code}: {get_resp.text}",
                before_state=None,
                after_state=None,
            )

        try:
            before_json: Any = get_resp.json()
            if not isinstance(before_json, dict) or "error_mode" not in before_json:
                return RemediationResult(
                    action_id=action.id,
                    status=RemediationExecutionStatus.FAILED,
                    started_at=started_at,
                    completed_at=datetime.now(UTC),
                    success=False,
                    summary="Unexpected response format from demo service GET /debug/error-mode.",
                    error=f"Expected dict with 'error_mode' key, got: {before_json}",
                    before_state=None,
                    after_state=None,
                )
            before_state: dict[str, Any] = {"error_mode": bool(before_json["error_mode"])}
        except Exception as exc:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Failed to parse JSON response from demo service GET /debug/error-mode.",
                error=str(exc),
                before_state=None,
                after_state=None,
            )

        # 3. Disable error mode (POST /debug/error-mode/false)
        post_resp, post_exc = await self._request_with_retry("POST", "/debug/error-mode/false")
        if post_resp is None:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.TIMED_OUT,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Demo service error-mode reset timed out after bounded retries.",
                error=f"Connection or timeout error during POST /debug/error-mode/false: {post_exc}",
                before_state=before_state,
                after_state=None,
            )

        if post_resp.status_code != 200:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary=f"Failed to reset demo service error mode (HTTP {post_resp.status_code}).",
                error=f"HTTP {post_resp.status_code}: {post_resp.text}",
                before_state=before_state,
                after_state=None,
            )

        try:
            after_model = DemoServiceErrorModeResponse.model_validate(post_resp.json())
            after_state = after_model.model_dump(mode="json")
        except Exception as exc:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Unexpected response format from demo service POST /debug/error-mode/false.",
                error=f"Invalid response schema: {exc}",
                before_state=before_state,
                after_state=None,
            )

        # 4. Verify post-condition: error_mode must be False
        if after_model.error_mode is not False:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Demo service error mode remains enabled after reset attempt.",
                error=f"Expected error_mode=False, received error_mode={after_model.error_mode}",
                before_state=before_state,
                after_state=after_state,
            )

        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            success=True,
            summary="Demo service simulated fault injection successfully reset.",
            before_state=before_state,
            after_state=after_state,
        )
