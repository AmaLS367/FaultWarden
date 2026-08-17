"""Unit tests for Change Intelligence nodes within LangGraph pipeline."""

from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.runnables import RunnableConfig

from faultwarden.graph.nodes.collect_changes import collect_recent_changes_node
from faultwarden.graph.nodes.correlate import correlate_evidence_node
from faultwarden.graph.nodes.hypothesize import generate_hypotheses_node
from faultwarden.graph.nodes.verify import verify_hypothesis_node
from faultwarden.integrations.change.base import ChangeProvider
from faultwarden.integrations.llm.provider import LLMProvider
from faultwarden.schemas.change import (
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)
from faultwarden.schemas.classification import IncidentCategory, IncidentClassification
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType
from faultwarden.schemas.hypothesis import (
    HypothesisCandidate,
    HypothesisGenerationResponse,
    HypothesisStatus,
    HypothesisVerificationResponse,
)


class MockChangeProvider(ChangeProvider):
    """Mock ChangeProvider returning a known deployment change."""

    def __init__(self, changes: list[OperationalChange]) -> None:
        self._changes = changes

    async def list_changes(
        self,
        service: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 50,
    ) -> list[OperationalChange]:
        return self._changes


class MockLLMProvider(LLMProvider):
    """Mock LLM returning structured hypotheses and verification."""

    async def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        return "Hypothesis generated"

    async def generate_structured(
        self,
        prompt: str,
        schema: type[Any],
        system_prompt: str | None = None,
    ) -> Any:
        if schema == HypothesisGenerationResponse:
            return HypothesisGenerationResponse(
                hypotheses=[
                    HypothesisCandidate(
                        title="Database Connection Pool Exhaustion after Config Change",
                        description="Deployment deploy-002 reduced DB_POOL_SIZE from 20 to 5, causing exhaustion.",
                        affected_component="demo-service",
                        confidence_score=0.90,
                        reasoning_summary="Matching logs and config change DB_POOL_SIZE",
                        supporting_evidence_ids=["ev-1"],
                        related_change_ids=["deploy-002"],
                    )
                ]
            )
        if schema == HypothesisVerificationResponse:
            return HypothesisVerificationResponse(
                is_verified=True,
                confidence_score=0.95,
                reasoning="Logs directly confirm DB_POOL_EXHAUSTED matches deploy-002 config reduction.",
                contradicting_evidence=[],
                missing_telemetry=[],
            )
        raise ValueError(f"Unsupported schema: {schema}")


@pytest.mark.asyncio
async def test_change_intelligence_graph_flow() -> None:
    """Test graph nodes executing change collection -> correlation -> hypothesis -> verification with causal linking."""
    now = datetime.now(UTC)

    test_change = OperationalChange(
        id="deploy-002",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy v1.0.1 (DB_POOL_SIZE: 20 -> 5)",
        timestamp=now,
        config_changes=[
            ConfigurationChange(
                key="DB_POOL_SIZE",
                old_value="20",
                new_value="5",
                component="database",
            )
        ],
    )

    change_provider = MockChangeProvider([test_change])
    llm_provider = MockLLMProvider()

    run_config: RunnableConfig = {
        "configurable": {
            "change_provider": change_provider,
            "llm_provider": llm_provider,
            "thread_id": "test-thread-change-1",
        }
    }

    # 1. Test collect_recent_changes_node
    state: dict[str, Any] = {
        "incident": {
            "id": "inc-100",
            "title": "High 5xx errors on demo-service",
            "service": "demo-service",
            "severity": "HIGH",
        },
        "evidence": [
            EvidenceItem(
                id="ev-1",
                evidence_type=EvidenceType.LOG,
                summary="[DB_POOL_EXHAUSTED] Database connection pool exhausted: active_connections=5/5",
                source="loki",
                timestamp=now,
            )
        ],
    }

    changes_res = await collect_recent_changes_node(state, config=run_config)  # type: ignore[arg-type]
    state.update(changes_res)

    assert len(state["recent_changes"]) == 1
    assert state["recent_changes"][0].id == "deploy-002"

    # 2. Test correlate_evidence_node
    state["classification"] = IncidentClassification(
        category=IncidentCategory.RESOURCE_EXHAUSTION,
        confidence=0.9,
        reasoning="DB pool error",
    )
    corr_res = await correlate_evidence_node(state, config=run_config)  # type: ignore[arg-type]
    state.update(corr_res)

    assert len(state["change_correlations"]) == 1
    assert len(state["candidate_causal_changes"]) == 1
    assert state["candidate_causal_changes"][0].id == "deploy-002"

    # 3. Test generate_hypotheses_node
    state["iteration_count"] = 1
    state["hypotheses"] = []
    state["selected_hypothesis"] = None
    hyp_res = await generate_hypotheses_node(state, config=run_config)  # type: ignore[arg-type]
    state.update(hyp_res)

    assert len(state["hypotheses"]) == 1
    hyp = state["hypotheses"][0]
    assert hyp.related_change_ids == ["deploy-002"]

    # 4. Test verify_hypothesis_node
    ver_res = await verify_hypothesis_node(state, config=run_config)  # type: ignore[arg-type]
    state.update(ver_res)

    assert state["investigation_status"] == "ROOT_CAUSE_IDENTIFIED"
    assert state["selected_hypothesis"] is not None
    assert state["selected_hypothesis"].status == HypothesisStatus.VERIFIED
    assert state["root_cause"] is not None
    assert state["root_cause"].causal_change_ids == ["deploy-002"]
    assert "deploy-002" in (state["root_cause"].causal_change_summary or "")
    assert state["selected_causal_change"] is not None
    assert state["selected_causal_change"].id == "deploy-002"
