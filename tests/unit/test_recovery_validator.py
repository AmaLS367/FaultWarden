"""Unit tests for deterministic multi-signal RecoveryValidator (Issue 3).

Invariants:
- Evaluates 4 signals:
  1. Executor target postcondition (e.g. error mode cleared).
  2. Target service /health endpoint returns 200.
  3. Prometheus 5xx error rate stays below threshold (e.g. 0.05) over validation window.
  4. Alert clearance verification.
- Fails if Prometheus is unreachable or returns invalid/no data (fail-safe).
- Deterministic and non-LLM.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from faultwarden.core.config import RemediationSettings
from faultwarden.schemas.evidence import MetricData, MetricDataPoint
from faultwarden.schemas.remediation import (
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    ValidationCheckResult,
)
from faultwarden.services.recovery_validator import RecoveryValidator


def _make_action() -> ResetDemoFailureExecutableAction:
    return ResetDemoFailureExecutableAction(
        id=str(uuid4()),
        proposal_id=str(uuid4()),
        policy_level=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        approval_required=False,
        executor="demo_service.reset_failure_mode",
        validated_parameters=ResetDemoFailureParameters(service="demo-service"),
    )


@pytest.mark.asyncio
async def test_recovery_validation_fails_when_prometheus_unreachable() -> None:
    """Recovery validation fails if Prometheus is unreachable or raises connection error."""
    mock_metrics = AsyncMock()
    mock_metrics.query.side_effect = Exception("Connection refused to Prometheus")

    validator = RecoveryValidator(
        metrics_provider=mock_metrics,
        settings=RemediationSettings(),
    )

    # Mock health and executor post-condition as successful
    validator._check_target_postcondition = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(
            name="target_postcondition", source="target_executor", passed=True
        )
    )
    validator._check_service_health = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(name="service_health", source="http_health", passed=True)
    )

    result = await validator.validate_recovery(_make_action())

    assert not result.passed
    prom_check = next(c for c in result.checks if c.source == "prometheus")
    assert not prom_check.passed
    assert prom_check.error is not None


@pytest.mark.asyncio
async def test_recovery_validation_fails_when_prometheus_returns_no_data() -> None:
    """Recovery validation fails if Prometheus returns None/empty (no data / metric vanished)."""
    mock_metrics = AsyncMock()
    mock_metrics.query.return_value = []

    validator = RecoveryValidator(
        metrics_provider=mock_metrics,
        settings=RemediationSettings(),
    )

    validator._check_target_postcondition = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(
            name="target_postcondition", source="target_executor", passed=True
        )
    )
    validator._check_service_health = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(name="service_health", source="http_health", passed=True)
    )

    result = await validator.validate_recovery(_make_action())

    assert not result.passed
    prom_check = next(c for c in result.checks if c.source == "prometheus")
    assert not prom_check.passed
    assert prom_check.error is not None


@pytest.mark.asyncio
async def test_recovery_validation_fails_when_error_rate_exceeds_threshold() -> None:
    """Recovery validation fails if 5xx error rate exceeds threshold (e.g. 0.15 >= 0.05)."""
    mock_metrics = AsyncMock()
    mock_metrics.query.return_value = [
        MetricData(
            query="test_5xx_rate",
            values=[MetricDataPoint(timestamp=datetime.now(UTC), value=0.15)],
        )
    ]

    validator = RecoveryValidator(
        metrics_provider=mock_metrics,
        settings=RemediationSettings(),
    )

    validator._check_target_postcondition = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(
            name="target_postcondition", source="target_executor", passed=True
        )
    )
    validator._check_service_health = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(name="service_health", source="http_health", passed=True)
    )

    result = await validator.validate_recovery(_make_action())

    assert not result.passed
    prom_check = next(c for c in result.checks if c.source == "prometheus")
    assert not prom_check.passed
    assert prom_check.observed_value == 0.15


@pytest.mark.asyncio
async def test_recovery_validation_passes_when_all_signals_healthy() -> None:
    """Recovery validation passes when postcondition, health, metric rate, and alerts all clear."""
    mock_metrics = AsyncMock()
    mock_metrics.query.return_value = [
        MetricData(
            query="test_5xx_rate",
            values=[MetricDataPoint(timestamp=datetime.now(UTC), value=0.001)],
        )
    ]

    validator = RecoveryValidator(
        metrics_provider=mock_metrics,
        settings=RemediationSettings(),
    )

    validator._check_target_postcondition = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(
            name="target_postcondition", source="target_executor", passed=True
        )
    )
    validator._check_service_health = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(name="service_health", source="http_health", passed=True)
    )
    validator._check_alert_cleared = AsyncMock(  # type: ignore[method-assign]
        return_value=ValidationCheckResult(name="alert_cleared", source="alertmanager", passed=True)
    )

    result = await validator.validate_recovery(_make_action())

    assert result.passed
    assert len(result.checks) >= 3
    assert all(c.passed for c in result.checks)
