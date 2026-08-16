"""Unit tests for Alertmanager payload validation and parsing."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from faultwarden.schemas.alert import AlertmanagerPayload


# --- Alertmanager Schema Validation Tests ---
def test_alertmanager_payload_valid_parsing(sample_alertmanager_payload: dict[str, Any]) -> None:
    """Ensure standard Alertmanager webhook payload parses cleanly."""

    payload = AlertmanagerPayload.model_validate(sample_alertmanager_payload)
    assert payload.version == "4"
    assert payload.status == "firing"
    assert payload.is_firing is True
    assert payload.is_resolved is False
    assert (
        payload.primary_alertname == "DemoServiceHighErrorRate"
        or payload.primary_alertname == "High5xxRate"
    )
    assert payload.primary_severity == "CRITICAL"
    assert payload.primary_fingerprint == "a1b2c3d4e5f6"
    assert payload.primary_service == "demo-service"
    assert len(payload.alerts) == 1
    assert payload.alerts[0].fingerprint == "a1b2c3d4e5f6"


def test_alertmanager_payload_resolved_parsing(sample_alertmanager_payload: dict[str, Any]) -> None:
    """Ensure resolved Alertmanager webhook payload parses correctly."""
    resolved_raw = dict(sample_alertmanager_payload)
    resolved_raw["status"] = "resolved"
    resolved_raw["alerts"] = [
        {
            **sample_alertmanager_payload["alerts"][0],
            "status": "resolved",
            "endsAt": datetime.now(UTC).isoformat(),
        }
    ]
    payload = AlertmanagerPayload.model_validate(resolved_raw)
    assert payload.status == "resolved"
    assert payload.is_resolved is True
    assert payload.is_firing is False
    assert payload.primary_fingerprint == "a1b2c3d4e5f6"


def test_alertmanager_payload_minimal_fields() -> None:
    """Ensure minimal valid Alertmanager payload structure parses."""
    now_iso = datetime.now(UTC).isoformat()
    raw = {
        "version": "4",
        "groupKey": "test_group",
        "status": "firing",
        "receiver": "webhook",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "PodCrashLooping"},
                "startsAt": now_iso,
            }
        ],
    }
    payload = AlertmanagerPayload.model_validate(raw)
    assert payload.primary_alertname == "PodCrashLooping"
    assert payload.primary_severity == "MEDIUM"  # default
    assert payload.primary_fingerprint == "test_group"  # fallback to groupKey


def test_alertmanager_payload_missing_required_fields() -> None:
    """Ensure validation error when required fields like status/receiver/groupKey are missing."""
    invalid_raw = {
        "version": "4",
        # missing groupKey, status, receiver
        "alerts": [],
    }
    with pytest.raises(ValidationError):
        AlertmanagerPayload.model_validate(invalid_raw)
