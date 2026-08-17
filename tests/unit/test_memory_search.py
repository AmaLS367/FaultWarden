"""Unit tests for cosine similarity calculation, search ranking, and incident exclusion."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.memory import IncidentMemoryModel
from faultwarden.integrations.embedding.provider import MockEmbeddingProvider
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.services.memory_service import MemoryService, calculate_cosine_similarity


# --- Test Cases ---
def test_cosine_similarity_math() -> None:
    """Test pure python cosine similarity calculation logic."""
    # Identical vectors -> 1.0
    v1 = [1.0, 0.0, 0.0]
    v2 = [1.0, 0.0, 0.0]
    assert pytest.approx(calculate_cosine_similarity(v1, v2), 0.001) == 1.0

    # Orthogonal vectors -> 0.0
    v3 = [0.0, 1.0, 0.0]
    assert pytest.approx(calculate_cosine_similarity(v1, v3), 0.001) == 0.0

    # Opposite vectors -> -1.0
    v4 = [-1.0, 0.0, 0.0]
    assert pytest.approx(calculate_cosine_similarity(v1, v4), 0.001) == -1.0

    # Empty / zero magnitude vectors -> 0.0
    assert calculate_cosine_similarity([], []) == 0.0
    assert calculate_cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0


@pytest.mark.asyncio
async def test_memory_similarity_search_ranking(db_session: AsyncSession) -> None:
    """Test searching stored memories and verifying ranked top-k results."""
    provider = MockEmbeddingProvider(dimensions=384)
    memory_svc = MemoryService(session=db_session, embedding_provider=provider)

    now = datetime.now(UTC)

    # 1. Insert Incident 1: Database Pool Exhaustion
    inc1 = IncidentModel(
        id=uuid4(),
        title="DB Pool Exhaustion Incident",
        service="order-service",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.RESOLVED,
        alert_payload={},
        created_at=now,
        updated_at=now,
    )
    db_session.add(inc1)
    await db_session.flush()

    emb1 = await provider.embed("Service: order-service\nCategory: DATABASE_ERROR\nPool exhausted.")
    mem1 = IncidentMemoryModel(
        incident_id=inc1.id,
        service="order-service",
        classification="DATABASE_ERROR",
        severity="HIGH",
        symptoms_summary="Pool exhausted",
        root_cause_summary="Connection pool exhausted",
        root_cause_category="DATABASE_ERROR",
        evidence_summary="Log: pool exhausted",
        successful_remediation_summary="Restarted pool",
        validation_summary="Validation passed",
        resolution_summary="Resolved",
        resolved_at=now,
        incident_duration_seconds=60.0,
        embedding=emb1,
        created_at=now,
    )
    db_session.add(mem1)

    # 2. Insert Incident 2: Memory Leak / OOM
    inc2 = IncidentModel(
        id=uuid4(),
        title="OOM Incident",
        service="payment-service",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.RESOLVED,
        alert_payload={},
        created_at=now,
        updated_at=now,
    )
    db_session.add(inc2)
    await db_session.flush()

    emb2 = await provider.embed(
        "Service: payment-service\nCategory: RESOURCE_EXHAUSTION\nOOM killed."
    )
    mem2 = IncidentMemoryModel(
        incident_id=inc2.id,
        service="payment-service",
        classification="RESOURCE_EXHAUSTION",
        severity="CRITICAL",
        symptoms_summary="OOM killed",
        root_cause_summary="Heap memory leak in cache layer",
        root_cause_category="RESOURCE_EXHAUSTION",
        evidence_summary="Metric: heap memory > 95%",
        successful_remediation_summary="Restarted container",
        validation_summary="Validation passed",
        resolution_summary="Resolved",
        resolved_at=now,
        incident_duration_seconds=120.0,
        embedding=emb2,
        created_at=now,
    )
    db_session.add(mem2)
    await db_session.commit()

    # Search for a database pool issue
    query = "Service: order-service\nCategory: DATABASE_ERROR\nPool exhausted."
    results = await memory_svc.search_similar(query=query, limit=5, min_similarity=0.1)

    assert len(results) >= 1
    assert results[0].incident_id == inc1.id
    assert results[0].root_cause_category == "DATABASE_ERROR"
    assert results[0].similarity > 0.8


@pytest.mark.asyncio
async def test_memory_similarity_search_exclusion(db_session: AsyncSession) -> None:
    """Test that exclude_incident_id correctly filters out the current incident."""
    provider = MockEmbeddingProvider(dimensions=384)
    memory_svc = MemoryService(session=db_session, embedding_provider=provider)

    now = datetime.now(UTC)
    inc = IncidentModel(
        id=uuid4(),
        title="Incident To Exclude",
        service="demo-service",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.RESOLVED,
        alert_payload={},
        created_at=now,
        updated_at=now,
    )
    db_session.add(inc)
    await db_session.flush()

    emb = await provider.embed("Some identical text")
    mem = IncidentMemoryModel(
        incident_id=inc.id,
        service="demo-service",
        classification="UNKNOWN",
        severity="HIGH",
        symptoms_summary="identical",
        root_cause_summary="identical",
        root_cause_category="UNKNOWN",
        evidence_summary="identical",
        successful_remediation_summary="identical",
        validation_summary="identical",
        resolution_summary="identical",
        resolved_at=now,
        incident_duration_seconds=10.0,
        embedding=emb,
        created_at=now,
    )
    db_session.add(mem)
    await db_session.commit()

    # Search with identical query and exclusion
    results_excluded = await memory_svc.search_similar(
        query="Some identical text",
        limit=5,
        min_similarity=0.1,
        exclude_incident_id=inc.id,
    )
    assert len(results_excluded) == 0

    # Search without exclusion -> finds it
    results_included = await memory_svc.search_similar(
        query="Some identical text",
        limit=5,
        min_similarity=0.1,
        exclude_incident_id=None,
    )
    assert len(results_included) == 1
    assert results_included[0].incident_id == inc.id
