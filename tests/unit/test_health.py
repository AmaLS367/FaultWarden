"""Unit tests for health and readiness endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    """Verify /health returns 200 OK."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "faultwarden"


@pytest.mark.asyncio
async def test_ready_endpoint(client: AsyncClient) -> None:
    """Verify /ready returns 200 OK and database health."""
    response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["checks"]["database"] == "healthy"


@pytest.mark.asyncio
async def test_metrics_endpoint(client: AsyncClient) -> None:
    """Verify /metrics returns Prometheus formatted text."""
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "faultwarden_http_requests_total" in response.text
