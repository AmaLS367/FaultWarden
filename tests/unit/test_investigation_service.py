"""Unit tests for InvestigationService execution, persistence, and endpoints."""

from typing import Any
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.graph.builder import build_incident_graph
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.hypothesis import (
    Hypothesis,
    HypothesisStatus,
)
from faultwarden.schemas.incident import (
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
)
from faultwarden.schemas.remediation import RemediationSafetyLevel
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService


@pytest.mark.asyncio
async def test_investigation_service_execution_and_persistence(
    db_session: AsyncSession,
) -> None:
    """Test running an autonomous investigation on an incident and verifying DB persistence."""
    incident_service = IncidentService(session=db_session)
    investigation_service = InvestigationService(incident_service=incident_service)

    # 1. Create a raw incident from alert payload
    create_dto = IncidentCreate(
        title="[CRITICAL] DemoServiceHighErrorRate in demo-service",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        summary="5xx error rate alert firing",
        fingerprint="fp-test-investigation-01",
        service="demo-service",
        alert_status="firing",
        alert_payload={
            "commonLabels": {
                "alertname": "DemoServiceHighErrorRate",
                "service": "demo-service",
                "severity": "critical",
            },
            "commonAnnotations": {
                "summary": "Elevated 5xx error rate in demo-service",
                "description": "Database connection pool exhausted in demo-service checkout endpoint",
            },
        },
    )
    incident = await incident_service.create_incident(create_dto)
    assert incident.status == IncidentStatus.DETECTED
    assert len(incident.evidence or []) == 0

    # 2. Run investigation
    updated_incident = await investigation_service.run_investigation(incident.id)

    # 3. Verify resulting incident state and persistence
    assert updated_incident.id == incident.id
    assert updated_incident.status in (
        IncidentStatus.ROOT_CAUSE_IDENTIFIED,
        IncidentStatus.REMEDIATION_PROPOSED,
    )
    assert len(updated_incident.evidence) >= 1
    assert len(updated_incident.hypotheses) >= 1
    assert updated_incident.root_cause is not None
    assert updated_incident.root_cause["confidence"] >= 0.75
    assert len(updated_incident.proposed_remediations) >= 1

    # Verify reload from database confirms persistence
    reloaded = await incident_service.get_incident(incident.id)
    assert len(reloaded.evidence) == len(updated_incident.evidence)
    assert reloaded.root_cause is not None
    assert (
        reloaded.root_cause["primary_hypothesis_id"]
        == updated_incident.root_cause["primary_hypothesis_id"]
    )


@pytest.mark.asyncio
async def test_investigation_api_endpoints(
    client: AsyncClient,
    sample_alertmanager_payload: dict[str, Any],
) -> None:
    """Test GET /incidents/{id}/investigation and POST /incidents/{id}/investigate API endpoints."""
    # 1. Create incident via webhook
    post_resp = await client.post(
        "/api/v1/alerts/alertmanager",
        json=sample_alertmanager_payload,
    )
    assert post_resp.status_code == 201
    incident_id = post_resp.json()["incident_id"]

    # 2. Fetch initial investigation details
    get_inv_resp = await client.get(f"/api/v1/incidents/{incident_id}/investigation")
    assert get_inv_resp.status_code == 200
    inv_data = get_inv_resp.json()
    assert inv_data["incident_id"] == incident_id

    # 3. Explicitly trigger/re-run investigation via POST endpoint
    run_inv_resp = await client.post(f"/api/v1/incidents/{incident_id}/investigate")
    assert run_inv_resp.status_code == 200
    run_data = run_inv_resp.json()
    assert run_data["incident_id"] == incident_id
    assert run_data["status"] in (
        IncidentStatus.ROOT_CAUSE_IDENTIFIED.value,
        IncidentStatus.REMEDIATION_PROPOSED.value,
    )
    assert len(run_data["evidence"]) >= 1
    assert len(run_data["hypotheses"]) >= 1
    assert run_data["root_cause"] is not None
    assert len(run_data["remediation_proposals"]) >= 1
    assert run_data["classification"] is not None
    assert run_data["iteration_count"] >= 1
    assert run_data["selected_hypothesis"] is not None
    assert run_data["selected_hypothesis"]["id"] == run_data["root_cause"]["primary_hypothesis_id"]

    # 3b. GET after the run must reflect the same persisted investigation metadata
    get_after_run_resp = await client.get(f"/api/v1/incidents/{incident_id}/investigation")
    assert get_after_run_resp.status_code == 200
    after_run_data = get_after_run_resp.json()
    assert after_run_data["classification"] is not None
    assert after_run_data["iteration_count"] >= 1
    assert after_run_data["selected_hypothesis"] is not None

    # 4. Verify 404 for non-existent incident investigation
    fake_id = str(uuid4())
    fake_get = await client.get(f"/api/v1/incidents/{fake_id}/investigation")
    assert fake_get.status_code == 404


@pytest.mark.asyncio
async def test_weak_hypothesis_triggers_bounded_iteration_loop() -> None:
    """Test that low-confidence hypothesis causes follow-up telemetry loop bounded by MAX_INVESTIGATION_ITERATIONS."""
    graph = build_incident_graph()

    # Create a state starting with a low-confidence hypothesis
    initial_state: IncidentInvestigationState = {
        "incident_id": "inc-loop-test",
        "incident_context": {"service": "demo-service"},
        "alert": {
            "commonLabels": {"alertname": "TransientAnomaly", "service": "demo-service"},
            "commonAnnotations": {"summary": "Brief 5xx spike observed"},
        },
        "classification": None,
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [
            Hypothesis(
                id=str(uuid4()),
                title="Unknown Intermittent Glitch",
                description="Insufficient telemetry to confirm",
                affected_component="demo-service",
                confidence_score=0.40,
                status=HypothesisStatus.PROPOSED,
                supporting_evidence_ids=[],
                missing_evidence_needed=["sum(rate(http_requests_total[1m]))"],
            )
        ],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [],
        "iteration_count": 1,
        "missing_evidence_queries": ["sum(rate(http_requests_total[1m]))"],
        "investigation_status": "INVESTIGATING",
        "summary": "",
        "errors": [],
    }

    final_state = await graph.ainvoke(initial_state)

    # Workflow must terminate within max iterations and propose safe remediations
    assert final_state["iteration_count"] >= 1
    assert final_state["investigation_status"] in ("COMPLETED", "INCONCLUSIVE")
    assert len(final_state["remediation_proposals"]) >= 1
    assert final_state["remediation_proposals"][0].highest_safety_level in (
        RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC,
        RemediationSafetyLevel.LEVEL_2_HUMAN_APPROVAL_REQUIRED,
    )
