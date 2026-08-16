"""Hypothesis generation node: produces candidate failure explanations from evidence."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableConfig

from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import get_llm_provider_from_config
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.llm.provider import wrap_untrusted_telemetry
from faultwarden.schemas.hypothesis import (
    Hypothesis,
    HypothesisGenerationResponse,
    HypothesisStatus,
)

logger = get_logger("faultwarden.graph.nodes.hypothesize")


# --- Hypothesis Generation Logic ---
async def generate_hypotheses_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,
) -> dict[str, Any]:
    """Generate structured candidate root-cause hypotheses from accumulated evidence."""
    incident_id = state.get("incident_id", "unknown")
    evidence_list = state.get("evidence", [])
    alert = state.get("alert", {})
    classification = state.get("classification")

    logger.info(
        "node_generate_hypotheses_start",
        incident_id=incident_id,
        evidence_count=len(evidence_list),
        iteration=state.get("iteration_count", 1),
    )

    # Prepare evidence inventory for LLM reasoning
    evidence_text_lines = []
    evidence_id_map = {}
    for idx, item in enumerate(evidence_list, start=1):
        evidence_id_map[item.id] = item
        evidence_text_lines.append(
            f"[{idx}] Evidence ID: {item.id} | Type: {item.evidence_type.value} | "
            f"Source: {item.source} | Summary: {item.summary}"
        )
    evidence_block = "\n".join(evidence_text_lines)

    # Wrap raw telemetry within trust boundary to safeguard against prompt injection
    protected_telemetry = wrap_untrusted_telemetry(evidence_block)

    classification_hint = (
        f"Category: {classification.category.value}\nReasoning: {classification.reasoning}"
        if classification
        else "Category: UNKNOWN"
    )

    prompt = (
        "Analyze the following incident telemetry and generate 1 to 3 plausible root-cause hypotheses.\n\n"
        f"Incident Classification Hint:\n{classification_hint}\n\n"
        f"Telemetry Evidence:\n{protected_telemetry}\n\n"
        "Guidelines:\n"
        "1. Every hypothesis MUST be strictly grounded in the telemetry evidence above.\n"
        "2. Reference exact supporting Evidence IDs in 'supporting_evidence_ids'.\n"
        "3. Specify what missing PromQL/LogQL queries could confirm or refute the hypothesis.\n"
        "4. Assign a realistic confidence score between 0.0 and 1.0 (do not hallucinate certainty).\n"
        "5. Do NOT execute or propose shell commands or code changes here."
    )

    system_prompt = (
        "You are FaultWarden's AI Root Cause Investigator. "
        "Your task is to impartially formulate candidate failure hypotheses based on telemetry."
    )

    llm = get_llm_provider_from_config(config)
    now = datetime.now(UTC)
    hypotheses: list[Hypothesis] = []
    node_errors: list[str] = []

    try:
        response: HypothesisGenerationResponse = await llm.generate_structured(
            prompt=prompt,
            schema=HypothesisGenerationResponse,
            system_prompt=system_prompt,
        )

        all_valid_ids = set(evidence_id_map.keys())

        for cand in response.hypotheses:
            # Filter referenced IDs to ensure they truly exist in our evidence inventory
            valid_supporting = [eid for eid in cand.supporting_evidence_ids if eid in all_valid_ids]
            # If model didn't fill in supporting IDs, associate all matching evidence by default
            if not valid_supporting and all_valid_ids:
                valid_supporting = list(all_valid_ids)

            hypotheses.append(
                Hypothesis(
                    id=str(uuid4()),
                    title=cand.title,
                    description=cand.description,
                    affected_component=cand.affected_component,
                    confidence_score=cand.confidence_score,
                    status=HypothesisStatus.PROPOSED,
                    supporting_evidence_ids=valid_supporting,
                    refuting_evidence_ids=[
                        eid for eid in cand.refuting_evidence_ids if eid in all_valid_ids
                    ],
                    verification_queries=[],
                    missing_evidence_needed=cand.missing_evidence_needed,
                    reasoning_summary=cand.reasoning_summary,
                    created_at=now,
                )
            )
    except Exception as exc:
        logger.warning(
            "llm_hypothesis_generation_failed_falling_back",
            incident_id=incident_id,
            error=str(exc),
        )
        node_errors.append(f"generate_hypotheses: LLM generation failed, using fallback: {exc}")

    # - Fallback Heuristic if LLM returned nothing or failed
    if not hypotheses:
        service_name = alert.get("commonLabels", {}).get("service", "demo-service")
        evidence_ids = [e.id for e in evidence_list]

        has_pool_error = any(
            "pool exhausted" in e.summary.lower() or "db_pool" in e.summary.lower()
            for e in evidence_list
        )

        if has_pool_error:
            hypotheses.append(
                Hypothesis(
                    id=str(uuid4()),
                    title="Database Connection Pool Exhaustion",
                    description="Service connection pool reached max capacity leading to queue timeouts and 500 errors.",
                    affected_component=service_name,
                    confidence_score=0.85,
                    status=HypothesisStatus.PROPOSED,
                    supporting_evidence_ids=evidence_ids,
                    reasoning_summary="Error logs explicitly indicate connection pool exhaustion during transactions.",
                    created_at=now,
                )
            )
        else:
            hypotheses.append(
                Hypothesis(
                    id=str(uuid4()),
                    title="Elevated Application Error Rate",
                    description="Incoming requests to service are encountering 5xx server exceptions.",
                    affected_component=service_name,
                    confidence_score=0.75,
                    status=HypothesisStatus.PROPOSED,
                    supporting_evidence_ids=evidence_ids,
                    reasoning_summary="Metrics show non-zero 5xx error rate on HTTP endpoints.",
                    created_at=now,
                )
            )

    logger.info(
        "hypotheses_generated",
        incident_id=incident_id,
        count=len(hypotheses),
        top_title=hypotheses[0].title if hypotheses else None,
    )

    return {
        "hypotheses": hypotheses,
        "errors": node_errors,
    }
