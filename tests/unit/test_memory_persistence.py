"""Unit tests for MemoryService persistence, quality policy gates, and pgvector storage."""

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
from faultwarden.integrations.embedding.provider import MockEmbeddingProvider
from faultwarden.schemas.evidence import EvidenceType
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import (
    ActionType,
    PolicyDecisionType,
    RemediationExecutionStatus,
    RemediationStatus,
    RemediationValidationStatus,
)
from faultwarden.services.memory_service import MemoryService


# --- Fixtures & Helpers ---
def _create_resolved_incident(
    *,
    service: str = "demo-service",
    with_evidence: bool = True,
    with_root_cause: bool = True,
) -> IncidentModel:
    now = datetime.now(UTC)
    uid = uuid4()
    evidence_list: list[dict[str, Any]] = []
    if with_evidence:
        evidence_list = [
            {
                "id": str(uuid4()),
                "evidence_type": EvidenceType.LOG.value,
                "source": "loki",
                "summary": "Database pool exhausted: connection queue timed out after 30s",
                "severity": "CRITICAL",
                "timestamp": now.isoformat(),
            }
        ]

    root_cause = None
    if with_root_cause:
        root_cause = {
            "primary_hypothesis_id": str(uuid4()),
            "summary": "Database connection pool exhausted under traffic spike.",
            "root_cause_category": "DATABASE_ERROR",
            "culprit_service": service,
            "confidence": 0.95,
            "identified_at": now.isoformat(),
        }

    return IncidentModel(
        id=uid,
        title=f"High latency on {service}",
        service=service,
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.RESOLVED,
        alert_payload={
            "groupLabels": {"alertname": "DatabasePoolExhausted"},
            "commonAnnotations": {"summary": f"Connection pool exhausted on {service}"},
        },
        classification={"category": "DATABASE_ERROR", "confidence": 0.95},
        evidence=evidence_list,
        hypotheses=[],
        root_cause=root_cause,
        resolution="Restarted connection pool and expanded pool size to 50.",
        created_at=now,
        updated_at=now,
    )


# --- Test Cases ---
@pytest.mark.asyncio
async def test_memory_indexing_success(db_session: AsyncSession) -> None:
    """Test indexing a fully resolved, high-quality incident."""
    now = datetime.now(UTC)
    incident = _create_resolved_incident()
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
        summary="Metrics recovered: error rate 0%, latency 12ms.",
        checks=[],
        started_at=now,
        completed_at=now,
    )
    db_session.add(validation)
    await db_session.commit()

    memory_svc = MemoryService(
        session=db_session,
        embedding_provider=MockEmbeddingProvider(dimensions=384),
    )

    # Check quality policy eligibility
    is_eligible, reason = await memory_svc.is_eligible_for_memory(incident)
    assert is_eligible is True
    assert "Incident meets all memory quality criteria" in reason

    # Index into memory
    memory = await memory_svc.index_incident_memory(incident)
    assert memory is not None
    assert memory.incident_id == incident.id
    assert memory.service == "demo-service"
    assert memory.root_cause_category == "DATABASE_ERROR"
    assert memory.embedding is not None
    assert len(memory.embedding) == 384


@pytest.mark.asyncio
async def test_memory_indexing_idempotent(db_session: AsyncSession) -> None:
    """Test that indexing the same incident multiple times is idempotent."""
    now = datetime.now(UTC)
    incident = _create_resolved_incident()
    db_session.add(incident)
    await db_session.flush()

    proposal = RemediationProposalModel(
        incident_id=incident.id,
        action_type=ActionType.RESET_DEMO_FAILURE,
        title="Reset Demo Service Fault",
        description="Reset",
        expected_effect="Restores 200",
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
        reason="Level 1",
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
        summary="Configuration reloaded.",
    )
    db_session.add(result)

    validation = RemediationValidationModel(
        incident_id=incident.id,
        action_id=action.id,
        status=RemediationValidationStatus.PASSED,
        passed=True,
        summary="Recovery verified.",
        checks=[],
        started_at=now,
        completed_at=now,
    )
    db_session.add(validation)
    await db_session.commit()

    memory_svc = MemoryService(
        session=db_session,
        embedding_provider=MockEmbeddingProvider(dimensions=384),
    )

    mem1 = await memory_svc.index_incident_memory(incident)
    assert mem1 is not None

    mem2 = await memory_svc.index_incident_memory(incident)
    assert mem2 is not None
    assert mem1.id == mem2.id


@pytest.mark.asyncio
async def test_memory_indexing_ineligible_unresolved(db_session: AsyncSession) -> None:
    """Test that non-resolved incidents fail the quality policy gate."""
    incident = _create_resolved_incident()
    incident.status = IncidentStatus.INVESTIGATING
    db_session.add(incident)
    await db_session.commit()

    memory_svc = MemoryService(session=db_session)
    is_eligible, reason = await memory_svc.is_eligible_for_memory(incident)
    assert is_eligible is False
    assert "INVESTIGATING" in reason

    mem = await memory_svc.index_incident_memory(incident)
    assert mem is None


@pytest.mark.asyncio
async def test_memory_indexing_ineligible_no_evidence(db_session: AsyncSession) -> None:
    """Test that incidents without evidence fail the quality policy gate."""
    incident = _create_resolved_incident(with_evidence=False)
    db_session.add(incident)
    await db_session.commit()

    memory_svc = MemoryService(session=db_session)
    is_eligible, reason = await memory_svc.is_eligible_for_memory(incident)
    assert is_eligible is False
    assert "evidence" in reason.lower()


@pytest.mark.asyncio
async def test_memory_indexing_ineligible_no_root_cause(db_session: AsyncSession) -> None:
    """Test that incidents without verified root cause fail the quality policy gate."""
    incident = _create_resolved_incident(with_root_cause=False)
    db_session.add(incident)
    await db_session.commit()

    memory_svc = MemoryService(session=db_session)
    is_eligible, reason = await memory_svc.is_eligible_for_memory(incident)
    assert is_eligible is False
    assert "root_cause" in reason.lower()
