"""Unit tests for bounded remediation executors and type-safe dispatcher."""

from collections.abc import Callable
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from faultwarden.core.config import RemediationSettings
from faultwarden.core.exceptions import RemediationExecutionError
from faultwarden.core.policy import evaluate_policy
from faultwarden.integrations.executors import (
    DemoServiceExecutor,
    RegisteredServiceExecutor,
    execute_remediation_action,
)
from faultwarden.schemas.remediation import (
    AllowedAction,
    ApprovalRequiredAction,
    DemoServiceErrorModeResponse,
    DemoServiceHealthResponse,
    RemediationExecutionStatus,
    RemediationResult,
    RemediationSafetyLevel,
    ResetDemoFailureExecutableAction,
    ResetDemoFailureParameters,
    ResetDemoFailureProposal,
    RestartRegisteredServiceExecutableAction,
    RestartRegisteredServiceParameters,
    RestartRegisteredServiceProposal,
)


# --- Mock Transport Helpers ---
def _install_mock_transport(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> None:
    """Route every httpx.AsyncClient instantiated during the test through a mock transport."""
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("transport", httpx.MockTransport(handler))
        real_init(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


# --- Fixtures ---
@pytest.fixture
def remediation_settings() -> RemediationSettings:
    """Provide standard test remediation settings."""
    return RemediationSettings(
        demo_service_url="http://test-demo-service:8001",
        execution_timeout_seconds=5.0,
        auto_execute_max_safety_level=2,
    )


@pytest.fixture
def reset_action(remediation_settings: RemediationSettings) -> ResetDemoFailureExecutableAction:
    """Construct real ResetDemoFailureExecutableAction via policy evaluation."""
    proposal = ResetDemoFailureProposal(
        id=str(uuid4()),
        incident_id="inc-test-reset",
        title="Reset Demo Error Injection",
        description="Clear simulated failure flag on demo service",
        expected_effect="200 OK responses restored",
        supporting_evidence_ids=["ev-1"],
        proposed_risk=RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        requires_approval=False,
        parameters=ResetDemoFailureParameters(service="demo-service"),
    )
    result = evaluate_policy(proposal, settings=remediation_settings)
    assert isinstance(result, AllowedAction)
    assert isinstance(result.action, ResetDemoFailureExecutableAction)
    return result.action


@pytest.fixture
def restart_action(
    remediation_settings: RemediationSettings,
) -> RestartRegisteredServiceExecutableAction:
    """Construct real RestartRegisteredServiceExecutableAction via policy evaluation."""
    proposal = RestartRegisteredServiceProposal(
        id=str(uuid4()),
        incident_id="inc-test-restart",
        title="Restart Demo Service",
        description="Perform controlled simulated restart of demo-service container",
        expected_effect="Memory leaks and frozen event loop cleared",
        supporting_evidence_ids=["ev-2"],
        proposed_risk=RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
        requires_approval=True,
        parameters=RestartRegisteredServiceParameters(service_id="demo-service"),
    )
    result = evaluate_policy(proposal, settings=remediation_settings)
    assert isinstance(result, (AllowedAction, ApprovalRequiredAction))
    assert isinstance(result.action, RestartRegisteredServiceExecutableAction)
    return result.action


# --- DemoServiceExecutor Tests ---
@pytest.mark.asyncio
async def test_demo_service_reset_success(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """reset_failure_mode succeeds against mocked endpoints: before_state True, after_state False."""
    requests_log: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_log.append(request)
        if request.method == "GET" and request.url.path == "/debug/error-mode":
            return httpx.Response(200, json={"error_mode": True})
        if request.method == "POST" and request.url.path == "/debug/error-mode/false":
            return httpx.Response(
                200,
                json={
                    "status": "updated",
                    "error_mode": False,
                    "message": "Error simulation set to False",
                },
            )
        return httpx.Response(404, text="Not Found")

    _install_mock_transport(monkeypatch, handler)

    executor = DemoServiceExecutor(remediation_settings)
    result = await executor.reset_failure_mode(reset_action)

    assert isinstance(result, RemediationResult)
    assert result.action_id == reset_action.id
    assert result.status == RemediationExecutionStatus.SUCCEEDED
    assert result.success is True
    assert result.error is None
    assert result.before_state == {"error_mode": True}
    assert result.after_state == {
        "status": "updated",
        "error_mode": False,
        "message": "Error simulation set to False",
    }
    assert result.before_state != result.after_state
    assert len(requests_log) == 2
    assert requests_log[0].method == "GET"
    assert requests_log[1].method == "POST"


@pytest.mark.asyncio
async def test_demo_service_reset_bounded_retries_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """reset_failure_mode retries exactly max_retries on ConnectError and returns TIMED_OUT."""
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("Connection refused by target", request=request)

    _install_mock_transport(monkeypatch, handler)

    executor = DemoServiceExecutor(remediation_settings)
    executor._retry_delay = 0.001  # accelerate test execution

    result = await executor.reset_failure_mode(reset_action)

    # 1 initial attempt + 2 retries = 3 total attempts
    assert attempts == 3
    assert isinstance(result, RemediationResult)
    assert result.action_id == reset_action.id
    assert result.status == RemediationExecutionStatus.TIMED_OUT
    assert result.success is False
    assert result.error is not None
    assert "Connection refused" in result.error
    assert result.before_state is None
    assert result.after_state is None


@pytest.mark.asyncio
async def test_demo_service_reset_post_timeout_after_get_success(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """POST error-mode times out after successful GET: captures before_state and returns TIMED_OUT."""
    post_attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal post_attempts
        if request.method == "GET" and request.url.path == "/debug/error-mode":
            return httpx.Response(200, json={"error_mode": True})
        if request.method == "POST" and request.url.path == "/debug/error-mode/false":
            post_attempts += 1
            raise httpx.ReadTimeout("Read timed out", request=request)
        return httpx.Response(404)

    _install_mock_transport(monkeypatch, handler)

    executor = DemoServiceExecutor(remediation_settings)
    executor._retry_delay = 0.001

    result = await executor.reset_failure_mode(reset_action)

    assert post_attempts == 3
    assert result.status == RemediationExecutionStatus.TIMED_OUT
    assert result.success is False
    assert result.before_state == {"error_mode": True}
    assert result.after_state is None


@pytest.mark.asyncio
async def test_demo_service_reset_non_2xx_returns_failed_no_raise(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """reset_failure_mode returns FAILED on 500 error and does not raise past the method."""
    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(500, text="Internal Server Error: DB down")

    _install_mock_transport(monkeypatch, handler)

    executor = DemoServiceExecutor(remediation_settings)
    executor._retry_delay = 0.001

    result = await executor.reset_failure_mode(reset_action)

    # HTTP 5xx is application failure, NOT transient connection error -> no retry
    assert attempts == 1
    assert isinstance(result, RemediationResult)
    assert result.status == RemediationExecutionStatus.FAILED
    assert result.success is False
    assert result.error is not None
    assert "HTTP 500" in result.error


@pytest.mark.asyncio
async def test_demo_service_reset_unexpected_payload_returns_failed(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """reset_failure_mode returns FAILED when response payload does not match schema."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"unexpected_key": 123})
        return httpx.Response(200, json={})

    _install_mock_transport(monkeypatch, handler)

    executor = DemoServiceExecutor(remediation_settings)
    result = await executor.reset_failure_mode(reset_action)

    assert result.status == RemediationExecutionStatus.FAILED
    assert result.success is False
    assert result.error is not None


@pytest.mark.asyncio
async def test_demo_service_reset_post_failure_mode_still_true_returns_failed(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """reset_failure_mode returns FAILED if POST returns error_mode=True."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"error_mode": True})
        return httpx.Response(
            200,
            json={"status": "error", "error_mode": True, "message": "Failed to clear flag"},
        )

    _install_mock_transport(monkeypatch, handler)

    executor = DemoServiceExecutor(remediation_settings)
    result = await executor.reset_failure_mode(reset_action)

    assert result.status == RemediationExecutionStatus.FAILED
    assert result.success is False
    assert "Expected error_mode=False" in str(result.error)


@pytest.mark.asyncio
async def test_demo_service_contract_violation_raises_remediation_execution_error(
    remediation_settings: RemediationSettings,
    restart_action: RestartRegisteredServiceExecutableAction,
) -> None:
    """Passing wrong action type to DemoServiceExecutor raises RemediationExecutionError."""
    executor = DemoServiceExecutor(remediation_settings)

    with pytest.raises(RemediationExecutionError) as exc_info:
        await executor.reset_failure_mode(restart_action)  # type: ignore[arg-type]

    assert "Invalid action type" in str(exc_info.value)
    assert exc_info.value.provider_name == "executor:demo_service"


# --- RegisteredServiceExecutor Tests ---
@pytest.mark.asyncio
async def test_registered_service_restart_success(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    restart_action: RestartRegisteredServiceExecutableAction,
) -> None:
    """restart succeeds against mocked /health and summary explicitly indicates simulation."""
    requests_log: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_log.append(request)
        if request.method == "GET" and request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok", "service": "demo-service"})
        return httpx.Response(404)

    _install_mock_transport(monkeypatch, handler)

    executor = RegisteredServiceExecutor(remediation_settings)
    result = await executor.restart(restart_action)

    assert isinstance(result, RemediationResult)
    assert result.action_id == restart_action.id
    assert result.status == RemediationExecutionStatus.SUCCEEDED
    assert result.success is True
    assert result.error is None
    assert "Simulated restart acknowledged for demo-service" in result.summary
    assert "no real process control exists in v0.3 demo scope" in result.summary
    assert result.before_state == {"status": "ok", "service": "demo-service"}
    assert result.after_state == {"status": "ok", "service": "demo-service"}
    assert len(requests_log) == 1
    assert requests_log[0].url.path == "/health"


@pytest.mark.asyncio
async def test_registered_service_restart_bounded_retries_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    restart_action: RestartRegisteredServiceExecutableAction,
) -> None:
    """restart retries bounded times on timeout and returns TIMED_OUT without raising."""
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectTimeout("Health check connection timed out", request=request)

    _install_mock_transport(monkeypatch, handler)

    executor = RegisteredServiceExecutor(remediation_settings)
    executor._retry_delay = 0.001

    result = await executor.restart(restart_action)

    assert attempts == 3
    assert isinstance(result, RemediationResult)
    assert result.status == RemediationExecutionStatus.TIMED_OUT
    assert result.success is False
    assert result.error is not None
    assert "Health check connection timed out" in result.error


@pytest.mark.asyncio
async def test_registered_service_restart_non_2xx_returns_failed(
    monkeypatch: pytest.MonkeyPatch,
    remediation_settings: RemediationSettings,
    restart_action: RestartRegisteredServiceExecutableAction,
) -> None:
    """restart returns FAILED when /health returns HTTP 503."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    _install_mock_transport(monkeypatch, handler)

    executor = RegisteredServiceExecutor(remediation_settings)
    result = await executor.restart(restart_action)

    assert result.status == RemediationExecutionStatus.FAILED
    assert result.success is False
    assert result.error is not None
    assert "HTTP 503" in result.error


@pytest.mark.asyncio
async def test_registered_service_contract_violation_raises_remediation_execution_error(
    remediation_settings: RemediationSettings,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """Passing wrong action type to RegisteredServiceExecutor raises RemediationExecutionError."""
    executor = RegisteredServiceExecutor(remediation_settings)

    with pytest.raises(RemediationExecutionError) as exc_info:
        await executor.restart(reset_action)  # type: ignore[arg-type]

    assert "Invalid action type" in str(exc_info.value)
    assert exc_info.value.provider_name == "executor:registered_service"


# --- Dispatcher Tests ---
@pytest.mark.asyncio
async def test_execute_remediation_action_dispatches_reset(
    monkeypatch: pytest.MonkeyPatch,
    reset_action: ResetDemoFailureExecutableAction,
) -> None:
    """execute_remediation_action dispatches ResetDemoFailureExecutableAction to DemoServiceExecutor."""
    mock_reset = AsyncMock(
        return_value=RemediationResult(
            action_id=reset_action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            success=True,
            summary="Mocked reset success",
        )
    )
    monkeypatch.setattr(DemoServiceExecutor, "reset_failure_mode", mock_reset)

    result = await execute_remediation_action(reset_action)

    assert mock_reset.await_count == 1
    mock_reset.assert_awaited_once_with(reset_action)
    assert result.status == RemediationExecutionStatus.SUCCEEDED
    assert result.summary == "Mocked reset success"


@pytest.mark.asyncio
async def test_execute_remediation_action_dispatches_restart(
    monkeypatch: pytest.MonkeyPatch,
    restart_action: RestartRegisteredServiceExecutableAction,
) -> None:
    """execute_remediation_action dispatches RestartRegisteredServiceExecutableAction to RegisteredServiceExecutor."""
    mock_restart = AsyncMock(
        return_value=RemediationResult(
            action_id=restart_action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            success=True,
            summary="Mocked restart success",
        )
    )
    monkeypatch.setattr(RegisteredServiceExecutor, "restart", mock_restart)

    result = await execute_remediation_action(restart_action)

    assert mock_restart.await_count == 1
    mock_restart.assert_awaited_once_with(restart_action)
    assert result.status == RemediationExecutionStatus.SUCCEEDED
    assert result.summary == "Mocked restart success"


@pytest.mark.asyncio
async def test_execute_remediation_action_unregistered_variant_raises() -> None:
    """execute_remediation_action raises RemediationExecutionError if action is not handled."""

    class FakeUnknownAction:
        action_type = "UNKNOWN_ACTION"

    with pytest.raises(RemediationExecutionError) as exc_info:
        await execute_remediation_action(FakeUnknownAction())  # type: ignore[arg-type]

    assert "No executor registered" in str(exc_info.value)
    assert exc_info.value.provider_name == "executor:dispatcher"


# --- Architectural Invariant Tests ---
def test_executor_target_urls_originate_only_from_settings(
    remediation_settings: RemediationSettings,
) -> None:
    """Assert executor client base_url originates strictly from RemediationSettings, never action params."""
    demo_exec = DemoServiceExecutor(remediation_settings)
    reg_exec = RegisteredServiceExecutor(remediation_settings)

    # 1. Base URL matches settings.demo_service_url exactly
    assert demo_exec._base_url == "http://test-demo-service:8001"
    assert reg_exec._base_url == "http://test-demo-service:8001"

    # 2. Base URL does not change regardless of custom parameters
    custom_settings = RemediationSettings(demo_service_url="http://custom-host:9999/")
    custom_demo_exec = DemoServiceExecutor(custom_settings)
    assert custom_demo_exec._base_url == "http://custom-host:9999"


# --- Response Schemas Validation Tests ---
def test_demo_service_response_schemas_validation() -> None:
    """DemoServiceErrorModeResponse and DemoServiceHealthResponse validate against expected payloads."""
    error_mode_data = {
        "status": "updated",
        "error_mode": False,
        "message": "Error simulation set to False",
    }
    model1 = DemoServiceErrorModeResponse.model_validate(error_mode_data)
    assert model1.status == "updated"
    assert model1.error_mode is False
    assert model1.message == "Error simulation set to False"

    health_data = {"status": "ok", "service": "demo-service"}
    model2 = DemoServiceHealthResponse.model_validate(health_data)
    assert model2.status == "ok"
    assert model2.service == "demo-service"
