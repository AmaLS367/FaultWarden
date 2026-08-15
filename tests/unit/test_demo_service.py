"""Unit tests for the breakable demo service."""

import pytest
from demo_service.app.main import app as demo_app
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_demo_service_healthy_and_error_mode_lifecycle() -> None:
    """Test demo service healthy behavior, error-mode injection, and metrics."""
    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://test-demo") as client:
        # 1. Check health
        health_resp = await client.get("/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["status"] == "ok"

        # 2. Normal request should succeed (200)
        root_resp = await client.get("/")
        assert root_resp.status_code == 200
        assert root_resp.json()["status"] == "healthy"

        # 3. Enable error mode
        toggle_on = await client.post("/debug/error-mode/true")
        assert toggle_on.status_code == 200
        assert toggle_on.json()["error_mode"] is True

        # 4. Request under error mode should fail (500)
        failing_resp = await client.get("/")
        assert failing_resp.status_code == 500

        # 5. Disable error mode
        toggle_off = await client.post("/debug/error-mode/false")
        assert toggle_off.status_code == 200
        assert toggle_off.json()["error_mode"] is False

        # 6. Request after recovery should succeed (200)
        recovered_resp = await client.get("/")
        assert recovered_resp.status_code == 200

        # 7. Check Prometheus metrics
        metrics_resp = await client.get("/metrics")
        assert metrics_resp.status_code == 200
        assert "demo_http_requests_total" in metrics_resp.text
