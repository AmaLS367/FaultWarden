"""Unit tests for the breakable demo service."""

import pytest
from demo_service.app.main import app as demo_app
from httpx import ASGITransport, AsyncClient


# --- Demo Service Lifecycle Tests ---
@pytest.mark.asyncio
async def test_demo_service_healthy_and_error_mode_lifecycle() -> None:
    """Test demo service healthy behavior, error-mode injection, and metrics."""
    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://test-demo") as client:
        # - 1. Health Probe & Normal Traffic
        health_resp = await client.get("/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["status"] == "ok"

        root_resp = await client.get("/")
        assert root_resp.status_code == 200
        assert root_resp.json()["status"] == "healthy"

        # - 2. Error Mode Activation & 500 Responses
        toggle_on = await client.post("/debug/error-mode/true")
        assert toggle_on.status_code == 200
        assert toggle_on.json()["error_mode"] is True

        failing_resp = await client.get("/")
        assert failing_resp.status_code == 500

        # - 3. Recovery & Metric Output
        toggle_off = await client.post("/debug/error-mode/false")
        assert toggle_off.status_code == 200
        assert toggle_off.json()["error_mode"] is False

        recovered_resp = await client.get("/")
        assert recovered_resp.status_code == 200

        metrics_resp = await client.get("/metrics")
        assert metrics_resp.status_code == 200
        assert "http_requests_total" in metrics_resp.text
        assert 'path="/"' in metrics_resp.text
        assert 'path="/debug/error-mode/{enabled}"' in metrics_resp.text
