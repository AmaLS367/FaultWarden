"""Unit tests for deterministic causal promotion gates and supporting evidence invariants (v0.5.1)."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from langchain_core.runnables import RunnableConfig

from faultwarden.core.causality import verify_causal_change_association
from faultwarden.graph.nodes.hypothesize import generate_hypotheses_node
from faultwarden.graph.nodes.verify import verify_hypothesis_node
from faultwarden.integrations.llm.provider import LLMProvider
from faultwarden.schemas.change import (
    CausalChangeType,
    ChangeCorrelation,
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType
from faultwarden.schemas.hypothesis import (
    Hypothesis,
    HypothesisCandidate,
    HypothesisGenerationResponse,
    HypothesisStatus,
    HypothesisVerificationResponse,
)


# --- Mock LLM for Testing Edge Cases ---
class ConfigurableMockLLM(LLMProvider):
    """Configurable Mock LLM returning pre-defined hypothesis or verification responses."""

    def __init__(
        self,
        gen_response: HypothesisGenerationResponse | None = None,
        ver_response: HypothesisVerificationResponse | None = None,
    ) -> None:
        self.gen_response = gen_response
        self.ver_response = ver_response

    async def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        return "mock text"

    async def generate_structured(
        self,
        prompt: str,
        schema: type[Any],
        system_prompt: str | None = None,
    ) -> Any:
        if schema == HypothesisGenerationResponse and self.gen_response is not None:
            return self.gen_response
        if schema == HypothesisVerificationResponse and self.ver_response is not None:
            return self.ver_response
        raise ValueError(f"Unexpected schema requested: {schema}")


# --- A. Causal Bypass Unit Tests ---
def test_same_service_unrelated_change_rejected_from_causal() -> None:
    """Test 1: Same-service change 1 min before incident, but symptom_match=False -> rejected from verified causal."""
    now = datetime.now(UTC)
    hyp = Hypothesis(
        id=str(uuid4()),
        title="Database pool exhausted",
        description="DB connections saturated",
        affected_component="demo-service",
        confidence_score=0.90,
        supporting_evidence_ids=["ev-log-1"],
        related_change_ids=["deploy-ui-banner"],
    )
    change = OperationalChange(
        id="deploy-ui-banner",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Update holiday banner css",
        timestamp=now,
    )
    corr = ChangeCorrelation(
        change_id="deploy-ui-banner",
        temporal_score=0.95,
        component_match=True,
        symptom_match=False,  # Unrelated styling change
        evidence_links=[],
        relevance_score=0.35,  # Capped due to symptom mismatch
        causal_category=CausalChangeType.UNRELATED_CHANGE,
        is_causal_candidate=False,
    )

    is_causal = verify_causal_change_association(
        hypothesis=hyp,
        change=change,
        correlation=corr,
        current_evidence_ids={"ev-log-1"},
        correlation_threshold=0.60,
    )
    assert is_causal is False


def test_post_incident_change_rejected_from_causal() -> None:
    """Test 2: Post-incident change referenced by LLM cannot become causal."""
    now = datetime.now(UTC)
    hyp = Hypothesis(
        id=str(uuid4()),
        title="Database pool exhausted",
        description="DB connections saturated",
        affected_component="demo-service",
        confidence_score=0.90,
        supporting_evidence_ids=["ev-log-1"],
        related_change_ids=["deploy-after-fact"],
    )
    change = OperationalChange(
        id="deploy-after-fact",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy hotfix",
        timestamp=now,
    )
    corr = ChangeCorrelation(
        change_id="deploy-after-fact",
        temporal_score=0.10,  # Post incident decay
        component_match=True,
        symptom_match=True,
        evidence_links=["ev-log-1"],
        relevance_score=0.45,
        causal_category=CausalChangeType.RESOURCE_LIMIT_CHANGE,
        is_causal_candidate=False,
    )

    is_causal = verify_causal_change_association(
        hypothesis=hyp,
        change=change,
        correlation=corr,
        current_evidence_ids={"ev-log-1"},
        correlation_threshold=0.60,
    )
    assert is_causal is False


def test_low_score_change_rejected_from_causal() -> None:
    """Test 3: Change with score below correlation threshold cannot become causal."""
    hyp = Hypothesis(
        id=str(uuid4()),
        title="Service degraded",
        description="Degraded performance",
        affected_component="demo-service",
        confidence_score=0.80,
        supporting_evidence_ids=["ev-1"],
        related_change_ids=["deploy-low-score"],
    )
    change = OperationalChange(
        id="deploy-low-score",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Misc refactor",
        timestamp=datetime.now(UTC),
    )
    corr = ChangeCorrelation(
        change_id="deploy-low-score",
        temporal_score=0.50,
        component_match=True,
        symptom_match=True,
        evidence_links=["ev-1"],
        relevance_score=0.55,  # Below 0.60 threshold
        is_causal_candidate=False,
    )

    is_causal = verify_causal_change_association(
        hypothesis=hyp,
        change=change,
        correlation=corr,
        current_evidence_ids={"ev-1"},
        correlation_threshold=0.60,
    )
    assert is_causal is False


def test_change_with_no_current_evidence_links_rejected_from_causal() -> None:
    """Test 4: Change with no valid active evidence links cannot become causal."""
    hyp = Hypothesis(
        id=str(uuid4()),
        title="Service degraded",
        description="Degraded",
        affected_component="demo-service",
        confidence_score=0.85,
        supporting_evidence_ids=["ev-active-1"],
        related_change_ids=["deploy-001"],
    )
    change = OperationalChange(
        id="deploy-001",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy v1.2",
        timestamp=datetime.now(UTC),
    )
    corr = ChangeCorrelation(
        change_id="deploy-001",
        temporal_score=0.90,
        component_match=True,
        symptom_match=True,
        evidence_links=["ev-deleted-old"],  # Not in active evidence inventory
        relevance_score=0.80,
        is_causal_candidate=True,
    )

    is_causal = verify_causal_change_association(
        hypothesis=hyp,
        change=change,
        correlation=corr,
        current_evidence_ids={"ev-active-1"},  # Does not contain ev-deleted-old
        correlation_threshold=0.60,
    )
    assert is_causal is False


def test_valid_db_pool_regression_promoted_to_causal() -> None:
    """Test 5: Valid DB_POOL_SIZE regression meeting all gates is promoted to verified causal."""
    hyp = Hypothesis(
        id=str(uuid4()),
        title="Database Connection Pool Exhaustion",
        description="DB connections saturated after config reduction",
        affected_component="demo-service",
        confidence_score=0.95,
        supporting_evidence_ids=["ev-log-1"],
        related_change_ids=["deploy-pool-regression"],
    )
    change = OperationalChange(
        id="deploy-pool-regression",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy v1.0.1: DB_POOL_SIZE changed 20 -> 5",
        timestamp=datetime.now(UTC),
        config_changes=[ConfigurationChange(key="DB_POOL_SIZE", old_value="20", new_value="5")],
    )
    corr = ChangeCorrelation(
        change_id="deploy-pool-regression",
        temporal_score=0.90,
        component_match=True,
        symptom_match=True,
        evidence_links=["ev-log-1"],
        relevance_score=0.85,
        causal_category=CausalChangeType.RESOURCE_LIMIT_CHANGE,
        is_causal_candidate=True,
    )

    is_causal = verify_causal_change_association(
        hypothesis=hyp,
        change=change,
        correlation=corr,
        current_evidence_ids={"ev-log-1", "ev-metric-1"},
        correlation_threshold=0.60,
    )
    assert is_causal is True


# --- B. Supporting Evidence Invariant Tests ---
@pytest.mark.asyncio
async def test_nonexistent_supporting_evidence_remains_empty() -> None:
    """Test 6: LLM returns hallucinated/nonexistent supporting_evidence_ids -> remains empty."""
    llm = ConfigurableMockLLM(
        gen_response=HypothesisGenerationResponse(
            hypotheses=[
                HypothesisCandidate(
                    title="Hypothesis with Fake Evidence",
                    description="Test",
                    affected_component="demo-service",
                    confidence_score=0.8,
                    supporting_evidence_ids=["ev-hallucinated-999", "ev-fake-123"],
                    refuting_evidence_ids=[],
                    historical_reference_ids=[],
                    related_change_ids=[],
                )
            ]
        )
    )

    state: dict[str, Any] = {
        "incident_id": "inc-1",
        "evidence": [
            EvidenceItem(
                id="ev-real-1",
                evidence_type=EvidenceType.METRIC,
                summary="5xx spike",
                source="prometheus",
                timestamp=datetime.now(UTC),
            )
        ],
    }
    config: RunnableConfig = {"configurable": {"llm_provider": llm}}

    res = await generate_hypotheses_node(state, config=config)  # type: ignore[arg-type]
    hyp = res["hypotheses"][0]
    assert hyp.supporting_evidence_ids == []


@pytest.mark.asyncio
async def test_change_id_in_supporting_evidence_migrated_to_related_changes() -> None:
    """Test 7: LLM returns a change ID inside supporting_evidence_ids -> stripped from evidence and migrated to related_change_ids."""
    llm = ConfigurableMockLLM(
        gen_response=HypothesisGenerationResponse(
            hypotheses=[
                HypothesisCandidate(
                    title="Hypothesis with Change ID as Evidence",
                    description="Test",
                    affected_component="demo-service",
                    confidence_score=0.8,
                    supporting_evidence_ids=["deploy-002"],  # Change ID, not an EvidenceItem
                    refuting_evidence_ids=[],
                    historical_reference_ids=[],
                    related_change_ids=[],
                )
            ]
        )
    )

    now = datetime.now(UTC)
    state: dict[str, Any] = {
        "incident_id": "inc-1",
        "evidence": [
            EvidenceItem(
                id="ev-real-1",
                evidence_type=EvidenceType.METRIC,
                summary="5xx spike",
                source="prometheus",
                timestamp=now,
            )
        ],
        "recent_changes": [
            OperationalChange(
                id="deploy-002",
                source="deployment",
                service="demo-service",
                change_type=ChangeType.DEPLOYMENT,
                title="Deploy v1.0.1",
                timestamp=now,
            )
        ],
    }
    config: RunnableConfig = {"configurable": {"llm_provider": llm}}

    res = await generate_hypotheses_node(state, config=config)  # type: ignore[arg-type]
    hyp = res["hypotheses"][0]
    # Invariant: Change ID cannot be supporting evidence
    assert hyp.supporting_evidence_ids == []
    # Invariant: Migrated to related_change_ids
    assert hyp.related_change_ids == ["deploy-002"]


@pytest.mark.asyncio
async def test_unsupported_hypothesis_cannot_be_verified_even_if_llm_claims_verified() -> None:
    """Test 9: Hypothesis with zero valid current supporting evidence cannot become VERIFIED even if LLM says is_verified=True."""
    now = datetime.now(UTC)
    unsupported_hyp = Hypothesis(
        id=str(uuid4()),
        title="Fabricated Root Cause",
        description="No telemetry supports this",
        affected_component="demo-service",
        confidence_score=1.0,
        supporting_evidence_ids=[],  # Zero supporting evidence
    )

    llm = ConfigurableMockLLM(
        ver_response=HypothesisVerificationResponse(
            is_verified=True,
            confidence_score=1.0,
            reasoning="LLM enthusiastically claims it is verified without evidence",
        )
    )

    state: dict[str, Any] = {
        "incident_id": "inc-1",
        "hypotheses": [unsupported_hyp],
        "evidence": [
            EvidenceItem(
                id="ev-1",
                evidence_type=EvidenceType.METRIC,
                summary="Unrelated telemetry",
                source="prometheus",
                timestamp=now,
            )
        ],
        "iteration_count": 1,
    }
    config: RunnableConfig = {"configurable": {"llm_provider": llm}}

    ver_res = await verify_hypothesis_node(state, config=config)  # type: ignore[arg-type]

    # Application gate MUST reject verification
    assert ver_res["selected_hypothesis"].status != HypothesisStatus.VERIFIED
    assert ver_res["root_cause"] is None


@pytest.mark.asyncio
async def test_historical_id_in_supporting_evidence_migrated_to_historical_refs() -> None:
    """Test 8: LLM returns historical incident ID inside supporting_evidence_ids -> stripped and migrated to historical_reference_ids."""
    hist_uuid = uuid4()
    llm = ConfigurableMockLLM(
        gen_response=HypothesisGenerationResponse(
            hypotheses=[
                HypothesisCandidate(
                    title="Hypothesis referencing past incident",
                    description="Inspired by past incident",
                    affected_component="demo-service",
                    confidence_score=0.8,
                    supporting_evidence_ids=[
                        str(hist_uuid)
                    ],  # Historical ID, not current evidence!
                    refuting_evidence_ids=[],
                    historical_reference_ids=[],
                    related_change_ids=[],
                )
            ]
        )
    )

    from faultwarden.schemas.memory import SimilarIncidentMemory

    state: dict[str, Any] = {
        "incident_id": "inc-1",
        "evidence": [
            EvidenceItem(
                id="ev-real-1",
                evidence_type=EvidenceType.METRIC,
                summary="5xx spike",
                source="prometheus",
                timestamp=datetime.now(UTC),
            )
        ],
        "similar_incidents": [
            SimilarIncidentMemory(
                incident_id=hist_uuid,
                memory_id=uuid4(),
                similarity=0.85,
                service="demo-service",
                classification="RESOURCE_EXHAUSTION",
                severity="HIGH",
                symptoms_summary="Past pool issue",
                root_cause_summary="Past pool exhaustion",
                root_cause_category="RESOURCE_EXHAUSTION",
                successful_remediation_summary="Reset pool",
                successful_action_type="RESET_DEMO_FAILURE",
                validation_summary="Recovered",
                resolved_at=datetime.now(UTC),
            )
        ],
    }
    config: RunnableConfig = {"configurable": {"llm_provider": llm}}

    res = await generate_hypotheses_node(state, config=config)  # type: ignore[arg-type]
    hyp = res["hypotheses"][0]

    # Invariant: Historical ID MUST NOT be in supporting_evidence_ids
    assert hyp.supporting_evidence_ids == []
    # Invariant: Migrated to historical_reference_ids
    assert str(hist_uuid) in hyp.historical_reference_ids


@pytest.mark.asyncio
async def test_fallback_attaches_only_matched_evidence() -> None:
    """Test 10: Fallback heuristic attaches only explicitly matched evidence, not all incident evidence."""
    now = datetime.now(UTC)
    # LLM fails / returns empty list
    llm = ConfigurableMockLLM(gen_response=HypothesisGenerationResponse(hypotheses=[]))

    ev_pool = EvidenceItem(
        id="ev-pool-log",
        evidence_type=EvidenceType.LOG,
        summary="[DB_POOL_EXHAUSTED] Database connection pool exhausted: active_connections=5/5",
        source="loki",
        timestamp=now,
    )
    ev_unrelated_metric = EvidenceItem(
        id="ev-disk-metric",
        evidence_type=EvidenceType.METRIC,
        summary="disk_utilization_percent = 42%",
        source="prometheus",
        timestamp=now,
    )

    state: dict[str, Any] = {
        "incident_id": "inc-1",
        "evidence": [ev_pool, ev_unrelated_metric],
        "candidate_causal_changes": [],
    }
    config: RunnableConfig = {"configurable": {"llm_provider": llm}}

    res = await generate_hypotheses_node(state, config=config)  # type: ignore[arg-type]
    hyp = res["hypotheses"][0]

    assert hyp.title == "Database Connection Pool Exhaustion"
    # MUST contain only ev-pool-log, NOT ev-disk-metric
    assert hyp.supporting_evidence_ids == ["ev-pool-log"]
    assert "ev-disk-metric" not in hyp.supporting_evidence_ids
