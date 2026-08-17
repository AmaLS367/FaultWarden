"""Unit tests enforcing the Architectural Trust Boundary:
Historical incidents are CONTEXT, NOT evidence.
Historical memory must never:
1. Directly set root_cause
2. Satisfy supporting_evidence requirements
3. Increase verified confidence by itself
4. Bypass remediation eligibility or policy
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from faultwarden.graph.nodes.hypothesize import generate_hypotheses_node
from faultwarden.graph.nodes.verify import verify_hypothesis_node
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.llm.provider import LLMProvider
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType
from faultwarden.schemas.hypothesis import (
    Hypothesis,
    HypothesisCandidate,
    HypothesisGenerationResponse,
    HypothesisStatus,
    HypothesisVerificationResponse,
)
from faultwarden.schemas.memory import SimilarIncidentMemory


class AdversarialLLMProvider(LLMProvider):
    """Mock LLM that tries to inject historical incident IDs as current supporting evidence."""

    def __init__(
        self,
        adversarial_supporting_ids: list[str],
        adversarial_confidence: float = 0.95,
    ) -> None:
        self.adversarial_supporting_ids = adversarial_supporting_ids
        self.adversarial_confidence = adversarial_confidence

    async def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        return "Adversarial response"

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
                        title="Adversarial Hypothesis",
                        description="Trying to verify via historical memory only.",
                        affected_component="demo-service",
                        confidence_score=self.adversarial_confidence,
                        supporting_evidence_ids=self.adversarial_supporting_ids,
                        refuting_evidence_ids=[],
                        historical_reference_ids=[],
                        missing_evidence_needed=[],
                        reasoning_summary="Based on historical similarity.",
                    )
                ]
            )
        if schema == HypothesisVerificationResponse:
            return HypothesisVerificationResponse(
                confidence_score=self.adversarial_confidence,
                is_verified=True,
                reasoning="Claiming verified based on historical reference.",
                additional_queries_needed=[],
            )
        raise ValueError(f"Unsupported schema: {schema}")


# --- Tests ---
@pytest.mark.asyncio
async def test_hypothesize_node_sanitizes_historical_ids() -> None:
    """If the LLM returns historical incident IDs in supporting_evidence_ids, the hypothesize node must strip them."""
    now = datetime.now(UTC)
    current_ev_id = str(uuid4())
    historical_id = str(uuid4())

    current_evidence = EvidenceItem(
        id=current_ev_id,
        evidence_type=EvidenceType.LOG,
        source="loki",
        summary="HTTP 500 status code rate spiked to 10%",
        severity="HIGH",
        timestamp=now,
    )

    sim_memory = SimilarIncidentMemory(
        memory_id=uuid4(),
        incident_id=UUID(historical_id),
        similarity=0.92,
        service="demo-service",
        classification="HTTP_ERROR",
        severity="CRITICAL",
        symptoms_summary="500 errors",
        root_cause_summary="Connection pool exhausted",
        root_cause_category="DATABASE_ERROR",
        evidence_summary="Log: pool exhausted",
        successful_remediation_summary="Restarted pool",
        validation_summary="Validated",
        resolution_summary="Resolved",
        created_at=now,
        resolved_at=now,
    )

    state: IncidentInvestigationState = {
        "incident_id": str(uuid4()),
        "evidence": [current_evidence],
        "similar_incidents": [sim_memory],
        "iteration_count": 1,
    }

    # Adversarial LLM puts both historical_id and current_ev_id into supporting_evidence_ids
    adversarial_llm = AdversarialLLMProvider(
        adversarial_supporting_ids=[historical_id, current_ev_id]
    )
    config = {"configurable": {"llm_provider": adversarial_llm}}

    res = await generate_hypotheses_node(state, config=config)

    hypotheses = res["hypotheses"]
    assert len(hypotheses) == 1
    hyp = hypotheses[0]

    # Invariant: historical_id MUST be stripped from supporting_evidence_ids
    assert historical_id not in hyp.supporting_evidence_ids
    assert hyp.supporting_evidence_ids == [current_ev_id]

    # Invariant: historical_id is migrated to historical_reference_ids
    assert historical_id in hyp.historical_reference_ids


@pytest.mark.asyncio
async def test_verify_node_rejects_verification_without_current_evidence() -> None:
    """Verify node MUST reject verification if candidate has only historical IDs and no current evidence."""
    now = datetime.now(UTC)
    current_ev_id = str(uuid4())
    fake_historical_id = str(uuid4())

    # Current telemetry in state
    current_evidence = EvidenceItem(
        id=current_ev_id,
        evidence_type=EvidenceType.METRIC,
        source="prometheus",
        summary="CPU usage at 45%",
        severity="LOW",
        timestamp=now,
    )

    # Candidate hypothesis has only fake_historical_id in supporting_evidence_ids (not in current evidence)
    candidate = Hypothesis(
        id=str(uuid4()),
        title="Unsubstantiated Hypothesis",
        description="Hypothesis with zero current supporting evidence.",
        affected_component="demo-service",
        confidence_score=0.99,
        status=HypothesisStatus.PROPOSED,
        supporting_evidence_ids=[fake_historical_id],
        refuting_evidence_ids=[],
        historical_reference_ids=[fake_historical_id],
        verification_queries=[],
        missing_evidence_needed=[],
        reasoning_summary="Inspired by historical memory only.",
        created_at=now,
    )

    state: IncidentInvestigationState = {
        "incident_id": str(uuid4()),
        "hypotheses": [candidate],
        "evidence": [current_evidence],
        "iteration_count": 1,
    }

    # LLM claims it is verified with 0.99 confidence
    adversarial_llm = AdversarialLLMProvider(
        adversarial_supporting_ids=[],
        adversarial_confidence=0.99,
    )
    config = {"configurable": {"llm_provider": adversarial_llm}}

    res = await verify_hypothesis_node(state, config=config)

    # Invariant: root_cause MUST NOT be verified
    assert res.get("root_cause") is None
    assert res["selected_hypothesis"].status in (
        HypothesisStatus.TESTING,
        HypothesisStatus.INCONCLUSIVE,
    )
