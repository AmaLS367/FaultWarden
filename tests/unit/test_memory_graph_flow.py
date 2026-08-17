"""Unit test for LangGraph execution with incident memory retrieval in the pipeline."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.memory import IncidentMemoryModel
from faultwarden.graph.builder import build_incident_graph
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.embedding.provider import MockEmbeddingProvider
from faultwarden.integrations.llm.provider import MockLLMProvider
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.schemas.remediation import (
    RemediationAction,
    RemediationExecutionStatus,
    RemediationResult,
)
from faultwarden.services.memory_service import MemoryService


@pytest.mark.asyncio
async def test_langgraph_pipeline_with_memory_retrieval(db_session: AsyncSession) -> None:
    """Test executing the full LangGraph investigation graph with memory retrieval node active."""
    provider = MockEmbeddingProvider(dimensions=384)
    memory_svc = MemoryService(session=db_session, embedding_provider=provider)

    now = datetime.now(UTC)

    # Pre-populate a historical incident memory
    hist_inc = IncidentModel(
        id=uuid4(),
        title="Historical Connection Pool Exhaustion",
        service="demo-service",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.RESOLVED,
        alert_payload={},
        created_at=now,
        updated_at=now,
    )
    db_session.add(hist_inc)
    await db_session.flush()

    emb = await provider.embed("Service: demo-service\nCategory: DATABASE_ERROR\nPool exhausted.")
    mem = IncidentMemoryModel(
        incident_id=hist_inc.id,
        service="demo-service",
        classification="DATABASE_ERROR",
        severity="CRITICAL",
        symptoms_summary="Database connection pool exhausted.",
        root_cause_summary="Connection pool max capacity reached.",
        root_cause_category="DATABASE_ERROR",
        evidence_summary="Log: database pool exhausted",
        successful_remediation_summary="Restarted demo-service",
        validation_summary="Validation confirmed recovery.",
        resolution_summary="Service recovered.",
        resolved_at=now,
        incident_duration_seconds=30.0,
        embedding=emb,
        created_at=now,
    )
    db_session.add(mem)
    await db_session.commit()

    # Compile Graph
    graph = build_incident_graph(checkpointer=None)

    initial_state: IncidentInvestigationState = {
        "incident_id": str(uuid4()),
        "alert": {
            "groupLabels": {"alertname": "HighHttpErrorRate", "service": "demo-service"},
            "commonLabels": {"service": "demo-service", "severity": "critical"},
            "commonAnnotations": {
                "summary": "Elevated 5xx error rates on demo-service",
                "description": "Error rate exceeded 5% threshold",
            },
        },
        "incident_context": {"service": "demo-service", "severity": "CRITICAL"},
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [],
        "remediation_all_policy_results": [],
        "remediation_prior_attempt_count": 0,
        "remediation_prior_auto_execution_count": 0,
        "iteration_count": 1,
        "missing_evidence_queries": [],
        "investigation_status": "STARTING",
        "errors": [],
    }

    async def _mock_executor(action: RemediationAction) -> RemediationResult:
        now_dt = datetime.now(UTC)
        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=now_dt,
            completed_at=now_dt,
            success=True,
            summary="Mock executed remediation",
        )

    async def _mock_validator(_act: Any) -> bool:
        return True

    run_config = {
        "configurable": {
            "llm_provider": MockLLMProvider(),
            "embedding_provider": provider,
            "memory_service": memory_svc,
            "remediation_executor": _mock_executor,
            "remediation_validator": _mock_validator,
        }
    }

    final_state = await graph.ainvoke(initial_state, config=run_config)

    # Verify that memory retrieval ran and retrieved the historical incident
    assert "similar_incidents" in final_state
    sim_list = final_state["similar_incidents"]
    assert len(sim_list) >= 1
    assert sim_list[0].incident_id == hist_inc.id

    # Verify that root cause was identified and validated
    assert final_state.get("root_cause") is not None
    assert final_state.get("remediation_validation_passed") is True
