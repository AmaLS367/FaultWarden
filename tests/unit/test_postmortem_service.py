"""Unit tests for PostmortemService: factual timeline generation, LLM synthesis, and heuristic fallback."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.remediation import (
    RemediationActionModel,
    RemediationProposalModel,
    RemediationResultModel,
    RemediationValidationModel,
)
from faultwarden.integrations.llm.provider import LLMProvider
from faultwarden.schemas.evidence import EvidenceType
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.schemas.postmortem import PostmortemSynthesisResponse
from faultwarden.schemas.remediation import (
    ActionType,
    PolicyDecisionType,
    RemediationExecutionStatus,
    RemediationStatus,
    RemediationValidationStatus,
)
from faultwarden.services.postmortem_service import PostmortemService


class MockPostmortemLLMProvider(LLMProvider):
    """Mock LLM returning valid structured postmortem synthesis response."""

    async def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        return "Postmortem summary"

    async def generate_structured(
        self,
        prompt: str,
        schema: type[Any],
        system_prompt: str | None = None,
    ) -> Any:
        if schema == PostmortemSynthesisResponse:
            return PostmortemSynthesisResponse(
                impact_summary="Service experienced elevated 5xx errors.",
                lessons_learned=["Monitor connection pool queue depth proactively."],
                follow_up_actions=[
                    "Increase connection pool size to 50",
                    "Add alert on pool utilization > 80%",
                ],
            )
        raise ValueError(f"Unsupported schema: {schema}")


# --- Tests ---
@pytest.mark.asyncio
async def test_postmortem_timeline_and_llm_synthesis(db_session: AsyncSession) -> None:
    """Test generating an ordered factual timeline and synthesized postmortem."""
    now = datetime.now(UTC)
    incident = IncidentModel(
        id=uuid4(),
        title="Database Connection Pool Exhaustion on demo-service",
        service="demo-service",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.RESOLVED,
        alert_payload={
            "groupLabels": {"alertname": "DatabasePoolExhausted"},
            "commonAnnotations": {"summary": "DB pool exhausted on demo-service"},
        },
        classification={"category": "DATABASE_ERROR", "confidence": 0.95},
        evidence=[
            {
                "id": str(uuid4()),
                "evidence_type": EvidenceType.LOG.value,
                "source": "loki",
                "summary": "Pool connection queue timeout",
                "severity": "CRITICAL",
                "timestamp": now.isoformat(),
            }
        ],
        root_cause={
            "primary_hypothesis_id": str(uuid4()),
            "summary": "Database connection pool exhausted.",
            "root_cause_category": "DATABASE_ERROR",
            "culprit_service": "demo-service",
            "confidence": 0.95,
            "identified_at": now.isoformat(),
        },
        resolution="Service restarted and verified.",
        created_at=now,
        updated_at=now,
    )
    db_session.add(incident)
    await db_session.flush()

    proposal = RemediationProposalModel(
        incident_id=incident.id,
        action_type=ActionType.RESET_DEMO_FAILURE,
        title="Reset Demo Service Fault Injection",
        description="Reset fault mode",
        expected_effect="Restores 200 responses",
        supporting_evidence_ids=[],
        proposed_risk=1,
        requires_approval=False,
        parameters={},
    )
    db_session.add(proposal)
    await db_session.flush()

    action = RemediationActionModel(
        proposal_id=proposal.id,
        incident_id=incident.id,
        decision=PolicyDecisionType.ALLOWED,
        action_type=ActionType.RESET_DEMO_FAILURE,
        policy_level=1,
        approval_required=False,
        executor="demo_service.reset_failure_mode",
        validated_parameters={},
        reason="Level 1 auto approved",
        status=RemediationStatus.APPROVED,
    )
    db_session.add(action)
    await db_session.flush()

    result = RemediationResultModel(
        action_id=action.id,
        status=RemediationExecutionStatus.SUCCEEDED,
        started_at=now,
        completed_at=now,
        success=True,
        summary="Service restarted successfully.",
    )
    db_session.add(result)

    validation = RemediationValidationModel(
        incident_id=incident.id,
        action_id=action.id,
        status=RemediationValidationStatus.PASSED,
        passed=True,
        summary="HTTP 200 health check passed.",
        checks=[],
        started_at=now,
        completed_at=now,
    )
    db_session.add(validation)
    await db_session.commit()

    # Use Mock Postmortem LLM
    postmortem_svc = PostmortemService(
        session=db_session,
        llm_provider=MockPostmortemLLMProvider(),
    )

    pm = await postmortem_svc.generate_and_persist_postmortem(
        incident=incident,
        similar_incident_ids=["hist-1", "hist-2"],
    )

    assert pm is not None
    assert pm.incident_id == incident.id
    assert "Database Connection Pool Exhaustion" in pm.title
    assert "Service experienced elevated 5xx errors" in pm.impact_summary
    assert len(pm.timeline) >= 4
    assert pm.similar_historical_incidents == ["hist-1", "hist-2"]
    assert len(pm.follow_up_actions) >= 1

    # Verify idempotency
    pm_second = await postmortem_svc.generate_and_persist_postmortem(incident)
    assert pm_second.id == pm.id


@pytest.mark.asyncio
async def test_postmortem_heuristic_fallback(db_session: AsyncSession) -> None:
    """Test generating postmortem with heuristic fallback when LLM fails or is absent."""
    now = datetime.now(UTC)
    incident = IncidentModel(
        id=uuid4(),
        title="High error rate on api-service",
        service="api-service",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.RESOLVED,
        alert_payload={},
        classification={"category": "HTTP_ERROR"},
        evidence=[],
        root_cause={"summary": "Downstream timeout."},
        resolution="Restarted api-service.",
        created_at=now,
        updated_at=now,
    )
    db_session.add(incident)
    await db_session.commit()

    # No LLM provider passed (None) -> uses deterministic heuristic synthesis
    postmortem_svc = PostmortemService(session=db_session, llm_provider=None)

    pm = await postmortem_svc.generate_and_persist_postmortem(incident)
    assert pm is not None
    assert pm.incident_id == incident.id
    assert "api-service" in pm.impact_summary or "api-service" in pm.title
    assert len(pm.follow_up_actions) >= 1
