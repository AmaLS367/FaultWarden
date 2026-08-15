"""Integration test for Alertmanager webhook to Incident lifecycle."""

from typing import Any
from uuid import uuid4

import pytest
from httpx import AsyncClient

from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus


@pytest.mark.asyncio
async def test_alertmanager_webhook_to_incident_persistence_and_retrieval(
    client: AsyncClient, sample_alertmanager_payload: dict[str, Any]
) -> None:
    """Test full flow: Alertmanager webhook -> Incident Creation -> DB Persistence -> Incident API retrieval."""

    # 1. Post Alertmanager webhook
    post_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json=sample_alertmanager_payload,
    )
    assert post_resp.status_code == 201
    ingest_data = post_resp.json()
    assert ingest_data["status"] == "received"
    incident_id = ingest_data["incident_id"]
    assert incident_id is not None
    assert ingest_data["incident_status"] == IncidentStatus.DETECTED.value

    # 2. Retrieve Incident by ID
    get_resp = await client.get(f"/api/v1/incidents/{incident_id}")
    assert get_resp.status_code == 200
    incident_data = get_resp.json()
    assert incident_data["id"] == incident_id
    assert incident_data["status"] == IncidentStatus.DETECTED.value
    assert incident_data["severity"] == IncidentSeverity.CRITICAL.value
    assert "High5xxRate" in incident_data["title"]
    assert incident_data["source"] == "alertmanager"
    assert incident_data["alert_payload"]["groupKey"] == sample_alertmanager_payload["groupKey"]

    # 3. List incidents with filter
    list_resp = await client.get(
        "/api/v1/incidents", params={"status": "DETECTED", "severity": "CRITICAL"}
    )
    assert list_resp.status_code == 200
    incidents_list = list_resp.json()
    assert len(incidents_list) >= 1
    assert any(inc["id"] == incident_id for inc in incidents_list)

    # 4. Request non-existent incident
    fake_id = str(uuid4())
    not_found_resp = await client.get(f"/api/v1/incidents/{fake_id}")
    assert not_found_resp.status_code == 404
    assert not_found_resp.json()["error"] == "Not Found"
