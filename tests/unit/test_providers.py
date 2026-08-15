"""Unit tests for provider interfaces and parsing logic."""

import pytest

from faultwarden.core.config import PrometheusSettings
from faultwarden.integrations.llm.provider import PlaceholderLLMProvider
from faultwarden.integrations.loki.client import LokiClient
from faultwarden.integrations.prometheus.client import PrometheusClient
from faultwarden.schemas.incident import IncidentRead


@pytest.mark.asyncio
async def test_placeholder_llm_provider() -> None:
    """Test deterministic placeholder LLM provider."""
    provider = PlaceholderLLMProvider()
    text_resp = await provider.generate_text("Analyze this incident log")
    assert "PlaceholderLLM" in text_resp

    structured_resp = await provider.generate_structured("Analyze this incident", IncidentRead)
    assert structured_resp is None or isinstance(structured_resp, IncidentRead)


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
