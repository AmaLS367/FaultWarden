"""Unit tests for Postmortem and Incident Memory causality hardening (v0.5.1)."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.models.incident import IncidentModel
from faultwarden.integrations.embedding.provider import MockEmbeddingProvider
from faultwarden.integrations.llm.provider import MockLLMProvider
from faultwarden.schemas.change import (
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType
from faultwarden.schemas.hypothesis import RootCauseAnalysis
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.services.memory_service import MemoryService
from faultwarden.services.postmortem_service import PostmortemService


@pytest.mark.asyncio
async def test_postmortem_and_memory_with_candidate_only_change(
    db_session: AsyncSession,
) -> None:
    """Test that an unverified candidate change does NOT appear as causal truth in postmortem or memory."""
    now = datetime.now(UTC)

    candidate_ch = OperationalChange(
        id="deploy-unrelated",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Unrelated deployment",
        timestamp=now,
    )

    ev = EvidenceItem(
        id="ev-1",
        evidence_type=EvidenceType.METRIC,
        summary="5xx spike",
        source="prometheus",
        timestamp=now,
    )

    # Root cause verified from telemetry, but NO verified causal change!
    root_cause = RootCauseAnalysis(
        primary_hypothesis_id=str(uuid4()),
        summary="Spike in network packet loss",
        root_cause_category="NETWORK",
        culprit_service="demo-service",
        causal_change_ids=[],  # Empty!
        causal_change_summary=None,
        confidence=0.90,
    )

    incident = IncidentModel(
        id=uuid4(),
        title="Network packet loss incident",
        service="demo-service",
        status=IncidentStatus.RESOLVED,
        severity=IncidentSeverity.MEDIUM,
        source="alertmanager",
        evidence=[ev.model_dump(mode="json")],
        recent_changes=[candidate_ch.model_dump(mode="json")],
        candidate_causal_changes=[candidate_ch.model_dump(mode="json")],
        causal_changes=[],  # No verified causal changes
        root_cause=root_cause.model_dump(mode="json"),
        resolution="Network switch restarted, recovery validated.",
    )
    db_session.add(incident)
    await db_session.commit()

    # 1. Postmortem Generation
    postmortem_svc = PostmortemService(
        session=db_session,
        llm_provider=MockLLMProvider(),
    )
    pm = await postmortem_svc.generate_and_persist_postmortem(incident)

    # Invariant: causal_change_summary in postmortem MUST be None
    assert pm.causal_change_summary is None

    # 2. Memory Indexing
    embedding = MockEmbeddingProvider(dimensions=384)
    memory_svc = MemoryService(
        session=db_session,
        embedding_provider=embedding,
    )
    mem = await memory_svc.index_incident_memory(incident, postmortem=pm)

    assert mem is not None
    # Invariant: Memory record MUST NOT contain unverified candidate change
    assert mem.causal_change_summary is None
    assert mem.causal_change_type is None


@pytest.mark.asyncio
async def test_postmortem_and_memory_with_verified_causal_change(
    db_session: AsyncSession,
) -> None:
    """Test that a verified causal change is recorded in postmortem and indexed in long-term memory."""
    now = datetime.now(UTC)

    verified_ch = OperationalChange(
        id="deploy-pool-5",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy v1.0.1 (DB_POOL_SIZE: 20 -> 5)",
        timestamp=now,
        config_changes=[ConfigurationChange(key="DB_POOL_SIZE", old_value="20", new_value="5")],
    )

    ev = EvidenceItem(
        id="ev-1",
        evidence_type=EvidenceType.LOG,
        summary="[DB_POOL_EXHAUSTED] Database connection pool exhausted",
        source="loki",
        timestamp=now,
    )

    root_cause = RootCauseAnalysis(
        primary_hypothesis_id=str(uuid4()),
        summary="Database pool exhaustion verified",
        root_cause_category="RESOURCE_EXHAUSTION",
        culprit_service="demo-service",
        causal_change_ids=["deploy-pool-5"],
        causal_change_summary="Deploy v1.0.1 (DB_POOL_SIZE: 20 -> 5) [deploy-pool-5]",
        technical_details={"causal_change_type": "RESOURCE_LIMIT_CHANGE"},
        confidence=0.95,
    )

    incident = IncidentModel(
        id=uuid4(),
        title="Database pool exhaustion on demo-service",
        service="demo-service",
        status=IncidentStatus.RESOLVED,
        severity=IncidentSeverity.HIGH,
        source="alertmanager",
        evidence=[ev.model_dump(mode="json")],
        recent_changes=[verified_ch.model_dump(mode="json")],
        candidate_causal_changes=[verified_ch.model_dump(mode="json")],
        causal_changes=[verified_ch.model_dump(mode="json")],
        root_cause=root_cause.model_dump(mode="json"),
        resolution="Reverted DB pool size to 20, recovery validated.",
    )
    db_session.add(incident)
    await db_session.commit()

    # 1. Postmortem Generation
    postmortem_svc = PostmortemService(
        session=db_session,
        llm_provider=MockLLMProvider(),
    )
    pm = await postmortem_svc.generate_and_persist_postmortem(incident)

    assert pm.causal_change_summary is not None
    assert "deploy-pool-5" in pm.causal_change_summary

    # 2. Memory Indexing
    embedding = MockEmbeddingProvider(dimensions=384)
    memory_svc = MemoryService(
        session=db_session,
        embedding_provider=embedding,
    )
    mem = await memory_svc.index_incident_memory(incident, postmortem=pm)

    assert mem is not None
    assert mem.causal_change_summary is not None
    assert "deploy-pool-5" in mem.causal_change_summary
    assert mem.causal_change_type == "RESOURCE_LIMIT_CHANGE"
