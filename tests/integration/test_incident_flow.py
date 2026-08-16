"""Integration test for Alertmanager webhook to Incident lifecycle."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from httpx import AsyncClient

from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus


# --- End-to-End Incident Lifecycle Test ---
@pytest.mark.asyncio
async def test_alertmanager_webhook_to_incident_persistence_and_retrieval(
    client: AsyncClient, sample_alertmanager_payload: dict[str, Any]
) -> None:
    """Test full flow: Alertmanager webhook -> Incident Creation -> DB Persistence -> Incident API retrieval."""
    # - 1. Webhook Ingestion & Incident Creation
    post_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json=sample_alertmanager_payload,
    )
    assert post_resp.status_code == 201
    ingest_data = post_resp.json()
    assert ingest_data["status"] == "created"
    incident_id = ingest_data["incident_id"]
    assert incident_id is not None
    assert ingest_data["incident_status"] == IncidentStatus.DETECTED.value
    assert ingest_data["fingerprint"] == "a1b2c3d4e5f6"

    # - 2. API Retrieval & Field Validation
    get_resp = await client.get(f"/api/v1/incidents/{incident_id}")
    assert get_resp.status_code == 200
    incident_data = get_resp.json()
    assert incident_data["id"] == incident_id
    assert incident_data["status"] == IncidentStatus.DETECTED.value
    assert incident_data["severity"] == IncidentSeverity.CRITICAL.value
    assert incident_data["fingerprint"] == "a1b2c3d4e5f6"
    assert incident_data["service"] == "demo-service"
    assert incident_data["alert_status"] == "firing"
    assert "High5xxRate" in incident_data["title"] or "DemoService" in incident_data["title"]
    assert incident_data["source"] == "alertmanager"
    assert incident_data["alert_payload"]["groupKey"] == sample_alertmanager_payload["groupKey"]
    assert incident_data["created_at"] is not None
    assert incident_data["updated_at"] is not None

    # - 3. Idempotency & Deduplication
    # Repeated FIRING alerts with the same fingerprint update existing active incident
    repeat_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json=sample_alertmanager_payload,
    )
    assert repeat_resp.status_code == 201
    repeat_data = repeat_resp.json()
    assert repeat_data["status"] == "updated"
    assert repeat_data["incident_id"] == incident_id

    # Verify incident count remains 1 for this fingerprint
    list_fp_resp = await client.get("/api/v1/incidents", params={"fingerprint": "a1b2c3d4e5f6"})
    assert list_fp_resp.status_code == 200
    assert len(list_fp_resp.json()) == 1

    # - 4. Distinct Fingerprint Tracking
    diff_payload = dict(sample_alertmanager_payload)
    diff_payload["groupKey"] = '{}:{alertname="HighMemoryUsage",service="demo-service"}'
    diff_payload["commonLabels"] = {
        "alertname": "HighMemoryUsage",
        "service": "demo-service",
        "severity": "warning",
    }
    diff_payload["alerts"] = [
        {
            **sample_alertmanager_payload["alerts"][0],
            "labels": {
                "alertname": "HighMemoryUsage",
                "service": "demo-service",
                "severity": "warning",
            },
            "fingerprint": "diff-fp-987654",
        }
    ]
    diff_resp = await client.post("/api/v1/alerts/alertmanager", json=diff_payload)
    assert diff_resp.status_code == 201
    diff_data = diff_resp.json()
    assert diff_data["status"] == "created"
    diff_incident_id = diff_data["incident_id"]
    assert diff_incident_id != incident_id

    # Verify total incidents count is now 2
    all_incidents_resp = await client.get("/api/v1/incidents")
    assert all_incidents_resp.status_code == 200
    assert len(all_incidents_resp.json()) == 2

    # - 5. Alert Resolution Lifecycle
    # Upstream RESOLVED webhook updates alert_status without prematurely closing the incident
    resolved_payload = dict(sample_alertmanager_payload)
    resolved_payload["status"] = "resolved"
    resolved_payload["alerts"] = [
        {
            **sample_alertmanager_payload["alerts"][0],
            "status": "resolved",
            "endsAt": datetime.now(UTC).isoformat(),
        }
    ]
    resolve_resp = await client.post("/api/v1/alerts/alertmanager", json=resolved_payload)
    assert resolve_resp.status_code == 201
    resolve_data = resolve_resp.json()
    assert resolve_data["status"] == "alert_resolved"
    assert resolve_data["incident_id"] == incident_id

    # Verify incident state in DB: alert_status is "resolved", but incident status remains DETECTED
    get_after_resolve = await client.get(f"/api/v1/incidents/{incident_id}")
    assert get_after_resolve.status_code == 200
    resolved_incident_data = get_after_resolve.json()
    assert resolved_incident_data["alert_status"] == "resolved"
    assert resolved_incident_data["status"] == IncidentStatus.DETECTED.value

    # - 6. Error & Validation Handling
    malformed_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json={"invalid": "payload"},
    )
    assert malformed_resp.status_code == 422

    fake_id = str(uuid4())
    not_found_resp = await client.get(f"/api/v1/incidents/{fake_id}")
    assert not_found_resp.status_code == 404
    assert not_found_resp.json()["error"] == "Not Found"

    # - 7. Re-firing After Resolution Starts a Fresh Incident
    # A later firing webhook on a fingerprint whose incident already resolved must NOT be
    # silently absorbed as a duplicate update of the resolved incident — it is a fresh
    # occurrence and must spawn a new incident (and thus a new investigation).
    refire_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json=sample_alertmanager_payload,
    )
    assert refire_resp.status_code == 201
    refire_data = refire_resp.json()
    assert refire_data["status"] == "created"
    assert refire_data["incident_id"] != incident_id

    list_fp_after_refire = await client.get(
        "/api/v1/incidents", params={"fingerprint": "a1b2c3d4e5f6"}
    )
    assert list_fp_after_refire.status_code == 200
    assert len(list_fp_after_refire.json()) == 2
