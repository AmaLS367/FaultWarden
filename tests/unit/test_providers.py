"""Unit tests for provider interfaces and parsing logic."""

from collections.abc import Callable
from datetime import UTC, datetime

import httpx
import pytest

from faultwarden.core.config import LokiSettings, PrometheusSettings
from faultwarden.core.exceptions import LokiError, PrometheusError
from faultwarden.integrations.llm.provider import PlaceholderLLMProvider
from faultwarden.integrations.loki.client import LokiClient
from faultwarden.integrations.prometheus.client import PrometheusClient
from faultwarden.schemas.incident import IncidentRead


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


# --- Placeholder LLM Tests ---
@pytest.mark.asyncio
async def test_placeholder_llm_provider() -> None:
    """Test deterministic placeholder LLM provider."""
    provider = PlaceholderLLMProvider()
    text_resp = await provider.generate_text("Analyze this incident log")
    assert "PlaceholderLLM" in text_resp

    structured_resp = await provider.generate_structured("Analyze this incident", IncidentRead)
    assert structured_resp is None or isinstance(structured_resp, IncidentRead)


# --- Prometheus Client Tests ---
def test_prometheus_parsing_logic() -> None:
    """Test Prometheus JSON vector/matrix response parsing."""
    client = PrometheusClient(PrometheusSettings(url="http://localhost:9090"))

    payload = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"service": "demo-service", "job": "demo"},
                    "value": [1723740000.0, "42.5"],
                }
            ],
        },
    }

    metrics = client._parse_result("up{job='demo'}", payload)
    assert len(metrics) == 1
    assert metrics[0].labels["service"] == "demo-service"
    assert len(metrics[0].values) == 1
    assert metrics[0].values[0].value == 42.5


# --- Loki Client Tests ---
def test_loki_parsing_logic() -> None:
    """Test Loki JSON stream response parsing."""

    client = LokiClient()

    payload = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"service": "demo-service", "level": "ERROR"},
                    "values": [
                        ["1723740000000000000", "Critical failure in payment worker"],
                    ],
                }
            ],
        },
    }

    logs = client._parse_result(payload)
    assert len(logs) == 1
    assert logs[0].level == "ERROR"
    assert "payment worker" in logs[0].message


@pytest.mark.asyncio
async def test_prometheus_query_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """query() should hit the instant-query endpoint and return parsed metrics."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/query"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [{"metric": {"service": "demo"}, "value": [1723740000.0, "5"]}],
                },
            },
        )

    _install_mock_transport(monkeypatch, handler)
    client = PrometheusClient(PrometheusSettings(url="http://prometheus.local"))

    metrics = await client.query("up", time=datetime.now(UTC))
    assert len(metrics) == 1
    assert metrics[0].values[0].value == 5.0


@pytest.mark.asyncio
async def test_prometheus_query_range_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """query_range() should hit the range-query endpoint and return parsed metrics."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/query_range"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "matrix",
                    "result": [
                        {
                            "metric": {"service": "demo"},
                            "values": [[1723740000.0, "1"], [1723740015.0, "2"]],
                        }
                    ],
                },
            },
        )

    _install_mock_transport(monkeypatch, handler)
    client = PrometheusClient(PrometheusSettings(url="http://prometheus.local"))

    now = datetime.now(UTC)
    metrics = await client.query_range("up", start=now, end=now)
    assert len(metrics) == 1
    assert len(metrics[0].values) == 2


@pytest.mark.asyncio
async def test_prometheus_query_http_error_raises_prometheus_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-200 response should raise PrometheusError with the status code."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    _install_mock_transport(monkeypatch, handler)
    client = PrometheusClient(PrometheusSettings(url="http://prometheus.local"))

    with pytest.raises(PrometheusError):
        await client.query("up")


@pytest.mark.asyncio
async def test_prometheus_query_connection_error_raises_prometheus_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transport-level connection failure should be wrapped in PrometheusError."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _install_mock_transport(monkeypatch, handler)
    client = PrometheusClient(PrometheusSettings(url="http://prometheus.local"))

    with pytest.raises(PrometheusError):
        await client.query("up")


@pytest.mark.asyncio
async def test_prometheus_check_health_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_health() should return True on a 200 response."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    _install_mock_transport(monkeypatch, handler)
    client = PrometheusClient(PrometheusSettings(url="http://prometheus.local"))

    assert await client.check_health() is True


@pytest.mark.asyncio
async def test_prometheus_check_health_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_health() should return False when the request fails."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _install_mock_transport(monkeypatch, handler)
    client = PrometheusClient(PrometheusSettings(url="http://prometheus.local"))

    assert await client.check_health() is False


@pytest.mark.asyncio
async def test_loki_query_range_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """query_range() should hit Loki's query_range endpoint and return parsed entries."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/loki/api/v1/query_range"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "stream": {"level": "ERROR"},
                            "values": [["1723740000000000000", "boom"]],
                        }
                    ],
                },
            },
        )

    _install_mock_transport(monkeypatch, handler)
    client = LokiClient(LokiSettings(url="http://loki.local"))

    now = datetime.now(UTC)
    logs = await client.query_range('{service="demo"}', start=now, end=now)
    assert len(logs) == 1
    assert logs[0].message == "boom"


@pytest.mark.asyncio
async def test_loki_query_range_http_error_raises_loki_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-200 response should raise LokiError with the status code."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad query")

    _install_mock_transport(monkeypatch, handler)
    client = LokiClient(LokiSettings(url="http://loki.local"))

    now = datetime.now(UTC)
    with pytest.raises(LokiError):
        await client.query_range('{service="demo"}', start=now, end=now)


@pytest.mark.asyncio
async def test_loki_query_range_connection_error_raises_loki_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transport-level connection failure should be wrapped in LokiError."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _install_mock_transport(monkeypatch, handler)
    client = LokiClient(LokiSettings(url="http://loki.local"))

    now = datetime.now(UTC)
    with pytest.raises(LokiError):
        await client.query_range('{service="demo"}', start=now, end=now)


@pytest.mark.asyncio
async def test_loki_check_health_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_health() should return True on a 200 response."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    _install_mock_transport(monkeypatch, handler)
    client = LokiClient(LokiSettings(url="http://loki.local"))

    assert await client.check_health() is True


@pytest.mark.asyncio
async def test_loki_check_health_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_health() should return False when the request fails."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _install_mock_transport(monkeypatch, handler)
    client = LokiClient(LokiSettings(url="http://loki.local"))

    assert await client.check_health() is False
