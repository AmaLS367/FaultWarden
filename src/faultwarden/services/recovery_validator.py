"""Multi-signal deterministic recovery validator for remediation actions."""

from datetime import UTC, datetime
from typing import Any

import httpx

from faultwarden.core.config import RemediationSettings, get_settings
from faultwarden.core.logging import get_logger
from faultwarden.integrations.prometheus.client import MetricsProvider, PrometheusClient
from faultwarden.schemas.remediation import (
    ActionType,
    RemediationAction,
    RemediationValidationResult,
    RemediationValidationStatus,
    ValidationCheckResult,
)

logger = get_logger("faultwarden.services.recovery_validator")


# --- Multi-Signal Deterministic Recovery Validator ---
class RecoveryValidator:
    """Evaluates multiple independent telemetry and health signals to verify service recovery.

    AGENTS.md / Issue 3 Invariants:
    - Never let an LLM own the recovery decision.
    - If Prometheus is unreachable or returns no data/error, validation MUST NOT pass.
    - Multi-signal checks: target postcondition, service health, 5xx rate, alert cleared.
    - Incident may transition to RESOLVED if and only if all checks explicitly pass.
    """

    def __init__(
        self,
        metrics_provider: MetricsProvider | None = None,
        settings: RemediationSettings | None = None,
    ) -> None:
        self.settings = settings or get_settings().remediation
        self.metrics_provider = metrics_provider or PrometheusClient()
        self.demo_service_url = self.settings.demo_service_url.rstrip("/")

    async def validate_recovery(
        self,
        action: RemediationAction,
    ) -> RemediationValidationResult:
        """Run all multi-signal deterministic validation checks against target service and telemetry."""
        action_id = action.id
        action_type = action.action_type
        started_at = datetime.now(UTC)

        logger.info(
            "recovery_validation_started",
            action_id=action_id,
            action_type=action_type.value,
        )

        checks: list[ValidationCheckResult] = []

        # 1. Target-specific post-condition check
        target_check = await self._check_target_postcondition(action)
        checks.append(target_check)

        # 2. Service health endpoint check
        health_check = await self._check_service_health()
        checks.append(health_check)

        # 3. Prometheus HTTP 5xx error rate check
        error_rate_check = await self._check_http_5xx_rate()
        checks.append(error_rate_check)

        # 4. Alert cleared / error symptom cleared check
        alert_check = await self._check_alert_cleared()
        checks.append(alert_check)

        completed_at = datetime.now(UTC)
        all_passed = all(c.passed for c in checks)
        overall_status = (
            RemediationValidationStatus.PASSED if all_passed else RemediationValidationStatus.FAILED
        )

        passed_names = [c.name for c in checks if c.passed]
        failed_checks = [f"{c.name} ({c.error or 'check failed'})" for c in checks if not c.passed]

        if all_passed:
            summary = (
                f"Multi-signal recovery validation passed: all {len(checks)} checks healthy "
                f"({', '.join(passed_names)})."
            )
        else:
            summary = (
                f"Recovery validation failed: {len(failed_checks)} of {len(checks)} checks failed: "
                f"{'; '.join(failed_checks)}."
            )

        logger.info(
            "recovery_validation_completed",
            action_id=action_id,
            passed=all_passed,
            status=overall_status.value,
            summary=summary,
        )

        return RemediationValidationResult(
            action_id=action_id,
            passed=all_passed,
            status=overall_status,
            started_at=started_at,
            completed_at=completed_at,
            summary=summary,
            checks=checks,
        )

    # --- Individual Check Handlers ---
    async def _check_target_postcondition(self, action: RemediationAction) -> ValidationCheckResult:
        """Check executor-specific postcondition state."""
        if action.action_type == ActionType.RESET_DEMO_FAILURE:
            try:
                async with httpx.AsyncClient(
                    base_url=self.demo_service_url, timeout=self.settings.execution_timeout_seconds
                ) as client:
                    resp = await client.get("/debug/error-mode")
                    if resp.status_code != 200:
                        return ValidationCheckResult(
                            name="TARGET_POSTCONDITION",
                            source="demo-service",
                            passed=False,
                            observed_value=f"HTTP {resp.status_code}",
                            expected_value="HTTP 200 with error_mode=False",
                            error=f"Unexpected status code {resp.status_code}: {resp.text}",
                        )
                    payload: Any = resp.json()
                    error_mode = payload.get("error_mode") if isinstance(payload, dict) else None
                    if error_mode is False:
                        return ValidationCheckResult(
                            name="TARGET_POSTCONDITION",
                            source="demo-service",
                            passed=True,
                            observed_value={"error_mode": False},
                            expected_value={"error_mode": False},
                        )
                    return ValidationCheckResult(
                        name="TARGET_POSTCONDITION",
                        source="demo-service",
                        passed=False,
                        observed_value={"error_mode": error_mode},
                        expected_value={"error_mode": False},
                        error=f"Target postcondition failed: error_mode is {error_mode}",
                    )
            except Exception as exc:
                return ValidationCheckResult(
                    name="TARGET_POSTCONDITION",
                    source="demo-service",
                    passed=False,
                    error=f"Postcondition check failed with exception: {exc}",
                )

        if action.action_type == ActionType.RESTART_REGISTERED_SERVICE:
            # For restart, verify the service is running and healthy
            try:
                async with httpx.AsyncClient(
                    base_url=self.demo_service_url, timeout=self.settings.execution_timeout_seconds
                ) as client:
                    resp = await client.get("/health")
                    passed = resp.status_code == 200
                    return ValidationCheckResult(
                        name="TARGET_POSTCONDITION",
                        source="demo-service",
                        passed=passed,
                        observed_value=f"HTTP {resp.status_code}",
                        expected_value="HTTP 200",
                        error=None
                        if passed
                        else f"Service restart postcondition HTTP {resp.status_code}",
                    )
            except Exception as exc:
                return ValidationCheckResult(
                    name="TARGET_POSTCONDITION",
                    source="demo-service",
                    passed=False,
                    error=f"Service restart postcondition check failed: {exc}",
                )

        return ValidationCheckResult(
            name="TARGET_POSTCONDITION",
            source="unknown",
            passed=False,
            error=f"No postcondition check defined for action type: {action.action_type}",
        )

    async def _check_service_health(self) -> ValidationCheckResult:
        """Check target service HTTP /health endpoint."""
        try:
            async with httpx.AsyncClient(
                base_url=self.demo_service_url, timeout=self.settings.execution_timeout_seconds
            ) as client:
                resp = await client.get("/health")
                if resp.status_code == 200:
                    data = (
                        resp.json()
                        if resp.headers.get("content-type", "").startswith("application/json")
                        else {}
                    )
                    return ValidationCheckResult(
                        name="SERVICE_HEALTH",
                        source="demo-service",
                        passed=True,
                        observed_value={"status_code": 200, "data": data},
                        expected_value={"status_code": 200},
                    )
                return ValidationCheckResult(
                    name="SERVICE_HEALTH",
                    source="demo-service",
                    passed=False,
                    observed_value={"status_code": resp.status_code},
                    expected_value={"status_code": 200},
                    error=f"Health endpoint returned HTTP {resp.status_code}: {resp.text}",
                )
        except Exception as exc:
            return ValidationCheckResult(
                name="SERVICE_HEALTH",
                source="demo-service",
                passed=False,
                error=f"Health endpoint connection error: {exc}",
            )

    async def _check_http_5xx_rate(self) -> ValidationCheckResult:
        """Check Prometheus 5xx error rate below threshold."""
        try:
            # Query rate over 1m window
            query = 'sum(rate(http_requests_total{status=~"5..", job="demo-service"}[1m]))'
            metrics = await self.metrics_provider.query(query)
            if not metrics:
                # Invariant: Prometheus unavailable or returning empty/no data MUST NOT pass
                return ValidationCheckResult(
                    name="HTTP_5XX_RATE",
                    source="prometheus",
                    passed=False,
                    observed_value=None,
                    expected_value=f"<= {self.settings.recovery_error_rate_threshold}",
                    error="Prometheus returned no metric data for 5xx rate check.",
                )

            # Get the latest data point
            latest_val = 0.0
            for m in metrics:
                if m.values:
                    latest_val += m.values[-1].value

            passed = latest_val <= self.settings.recovery_error_rate_threshold
            return ValidationCheckResult(
                name="HTTP_5XX_RATE",
                source="prometheus",
                passed=passed,
                observed_value=latest_val,
                expected_value=f"<= {self.settings.recovery_error_rate_threshold}",
                error=None
                if passed
                else f"5xx error rate ({latest_val:.4f} req/s) exceeds threshold ({self.settings.recovery_error_rate_threshold:.4f} req/s)",
            )
        except Exception as exc:
            return ValidationCheckResult(
                name="HTTP_5XX_RATE",
                source="prometheus",
                passed=False,
                error=f"Prometheus query failed: {exc}",
            )

    async def _check_alert_cleared(self) -> ValidationCheckResult:
        """Check that alert condition symptom has cleared."""
        try:
            query = 'sum(rate(http_requests_total{status=~"5..", job="demo-service"}[1m]))'
            metrics = await self.metrics_provider.query(query)
            if not metrics:
                return ValidationCheckResult(
                    name="ALERT_CLEARED",
                    source="prometheus",
                    passed=False,
                    observed_value=None,
                    expected_value="rate == 0",
                    error="Prometheus returned no metric data for alert clearance check.",
                )

            total_rate = 0.0
            for m in metrics:
                if m.values:
                    total_rate += m.values[-1].value

            # Alert is considered cleared if error rate is 0 or below threshold
            passed = total_rate <= self.settings.recovery_error_rate_threshold
            return ValidationCheckResult(
                name="ALERT_CLEARED",
                source="prometheus",
                passed=passed,
                observed_value=total_rate,
                expected_value=f"<= {self.settings.recovery_error_rate_threshold}",
                error=None if passed else f"Alert symptom active with 5xx rate {total_rate:.4f}",
            )
        except Exception as exc:
            return ValidationCheckResult(
                name="ALERT_CLEARED",
                source="prometheus",
                passed=False,
                error=f"Prometheus alert clearance query failed: {exc}",
            )
