"""Registered service remediation executor for simulated restart operations."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx

from faultwarden.core.config import RemediationSettings, get_settings
from faultwarden.core.exceptions import RemediationExecutionError
from faultwarden.core.logging import get_logger
from faultwarden.schemas.remediation import (
    DemoServiceHealthResponse,
    RemediationExecutionStatus,
    RemediationResult,
    RestartRegisteredServiceExecutableAction,
)

logger = get_logger("faultwarden.integrations.executors.registered_service")

# Transient transport errors eligible for bounded retries
_TRANSIENT_EXCEPTIONS = (httpx.ConnectError, httpx.TimeoutException)


# --- Registered Service Executor ---
class RegisteredServiceExecutor:
    """Bounded executor for simulated service restart operations."""

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

    async def _check_health_with_retry(
        self,
    ) -> tuple[httpx.Response | None, Exception | None]:
        """Perform health check request with bounded retries on transient connection/timeout failures."""
        last_exc: Exception | None = None
        for attempt in range(1 + self._max_retries):
            try:
                async with await self._get_client() as client:
                    resp = await client.get("/health")
                    return resp, None
            except _TRANSIENT_EXCEPTIONS as exc:
                last_exc = exc
                logger.warning(
                    "registered_service_health_transient_error",
                    path="/health",
                    attempt=attempt + 1,
                    max_attempts=1 + self._max_retries,
                    error=str(exc),
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(self._retry_delay)

        return None, last_exc

    async def check_recovered(self) -> bool:
        """Level-0 read-only post-remediation check: is the target reachable/healthy?

        Since this executor's restart is a simulation (no real process control exists in v0.3),
        "recovered" means the target is still reachable — there is no other real state to verify.
        """
        resp, exc = await self._check_health_with_retry()
        if resp is None or resp.status_code != 200:
            logger.warning(
                "registered_service_validation_check_failed",
                error=str(exc) if exc else f"HTTP {resp.status_code if resp else 'no response'}",
            )
            return False
        return True

    async def restart(self, action: RestartRegisteredServiceExecutableAction) -> RemediationResult:
        """Simulated restart capability for the demo environment (no real process/container control).

        Error contract:
        - Programming-contract violations (wrong action type) raise RemediationExecutionError.
        - All external HTTP/I/O outcomes (success, non-2xx, parse errors, timeout/connection
          exhaustion) return a typed RemediationResult (SUCCEEDED, FAILED, TIMED_OUT)
          so the orchestration workflow can audit and persist the outcome.
        """
        # 1. Enforce programming contract before performing any I/O
        if not isinstance(action, RestartRegisteredServiceExecutableAction):
            raise RemediationExecutionError(
                "registered_service",
                f"Invalid action type for RegisteredServiceExecutor: {type(action).__name__}",
            )

        started_at = datetime.now(UTC)

        # 2. Check target reachability via /health
        resp, exc = await self._check_health_with_retry()
        if resp is None:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.TIMED_OUT,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Target service health check timed out after bounded retries.",
                error=f"Connection or timeout error during GET /health: {exc}",
                before_state=None,
                after_state=None,
            )

        if resp.status_code != 200:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary=f"Simulated restart failed: health check returned HTTP {resp.status_code}.",
                error=f"HTTP {resp.status_code}: {resp.text}",
                before_state=None,
                after_state=None,
            )

        try:
            health_model = DemoServiceHealthResponse.model_validate(resp.json())
            state_data: dict[str, Any] = health_model.model_dump(mode="json")
        except Exception as parse_exc:
            return RemediationResult(
                action_id=action.id,
                status=RemediationExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                success=False,
                summary="Unexpected response format from demo service GET /health.",
                error=f"Invalid response schema: {parse_exc}",
                before_state=None,
                after_state=None,
            )

        # 3. Honest simulation reporting: target is verified healthy, no actual mutation occurred
        summary = (
            f"Simulated restart acknowledged for {action.validated_parameters.service_id}; "
            "no real process control exists in v0.3 demo scope."
        )

        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            success=True,
            summary=summary,
            before_state=state_data,
            after_state=state_data,
        )
