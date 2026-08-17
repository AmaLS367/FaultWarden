"""Hypothesis generation node: produces candidate failure explanations from evidence and change intelligence."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableConfig

from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import (
    get_llm_provider_from_config,
    resolve_service_from_state,
)
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.llm.provider import wrap_untrusted_telemetry
from faultwarden.schemas.change import sanitize_change_for_prompt
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
    """Generate structured candidate root-cause hypotheses from accumulated evidence and change intelligence."""
    incident_id = state.get("incident_id", "unknown")
    evidence_list = state.get("evidence", [])
    classification = state.get("classification")
    similar_incidents = state.get("similar_incidents", [])
    recent_changes = state.get("recent_changes", [])
    candidate_causal_changes = state.get("candidate_causal_changes", [])

    logger.info(
        "node_generate_hypotheses_start",
        incident_id=incident_id,
        evidence_count=len(evidence_list),
        similar_incidents_count=len(similar_incidents),
        recent_changes_count=len(recent_changes),
        candidate_causal_changes_count=len(candidate_causal_changes),
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

    # Format historical reference context (CONTEXT ONLY - NOT CURRENT EVIDENCE)
    historical_block = ""
    if similar_incidents:
        hist_lines = []
        for idx, sim in enumerate(similar_incidents, start=1):
            hist_lines.append(
                f"[{idx}] Historical Incident ID: {sim.incident_id} | Similarity: {sim.similarity:.2f} | "
                f"Service: {sim.service} | Category: {sim.root_cause_category}\n"
                f"    Past Symptoms: {sim.symptoms_summary}\n"
                f"    Past Root Cause: {sim.root_cause_summary}\n"
                f"    Past Resolution: {sim.successful_remediation_summary}"
            )
        historical_block = (
            "HISTORICAL REFERENCE INCIDENTS (BACKGROUND CONTEXT ONLY — NOT CURRENT EVIDENCE):\n"
            + "\n".join(hist_lines)
            + "\n\n"
        )

    # Format recent changes context (POTENTIAL CAUSAL TRIGGERS — NOT TELEMETRY EVIDENCE)
    changes_block = ""
    if recent_changes:
        ch_lines = [sanitize_change_for_prompt(ch) for ch in recent_changes]
        changes_block = (
            "RECENT OPERATIONAL CHANGES (COMMITS, DEPLOYMENTS, CONFIG DIFFS — POTENTIAL CAUSAL TRIGGERS):\n"
            + "\n".join(ch_lines)
            + "\n\n"
        )

    prompt = (
        "Analyze the following incident telemetry, historical context, and recent changes to generate 1 to 3 plausible root-cause hypotheses.\n\n"
        f"Incident Classification Hint:\n{classification_hint}\n\n"
        f"{historical_block}"
        f"{changes_block}"
        f"Current Telemetry Evidence:\n{protected_telemetry}\n\n"
        "Guidelines:\n"
        "1. Every hypothesis MUST be strictly grounded in the Current Telemetry Evidence above.\n"
        "2. Historical reference incidents are background context ONLY; they are NOT current evidence.\n"
        "3. Recent operational changes are potential causal factors; they are NOT current telemetry evidence.\n"
        "4. Reference exact current Evidence IDs in 'supporting_evidence_ids'. Do NOT put change IDs or historical incident IDs in supporting_evidence_ids.\n"
        "5. If a hypothesis links the incident to a specific recent change, include that change's ID in 'related_change_ids'.\n"
        "6. If a hypothesis was inspired by a historical reference incident, include that historical incident ID in 'historical_reference_ids'.\n"
        "7. Specify what missing PromQL/LogQL queries could confirm or refute the hypothesis.\n"
        "8. Assign a realistic confidence score between 0.0 and 1.0 (do not hallucinate certainty).\n"
        "9. Do NOT execute or propose shell commands or code changes here."
    )

    system_prompt = (
        "You are FaultWarden's AI Root Cause Investigator. "
        "Your task is to impartially formulate candidate failure hypotheses based on telemetry and change intelligence."
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
        all_historical_ids = {str(sim.incident_id) for sim in similar_incidents}
        all_change_ids = {ch.id for ch in recent_changes}

        for cand in response.hypotheses:
            # Deterministic trust boundary guard: filter supporting_evidence_ids strictly against current evidence
            valid_supporting = [eid for eid in cand.supporting_evidence_ids if eid in all_valid_ids]

            # Separate and preserve historical reference IDs
            valid_historical_refs = [
                hid for hid in cand.historical_reference_ids if hid in all_historical_ids
            ]
            # Separate and preserve related change IDs
            valid_change_refs = [cid for cid in cand.related_change_ids if cid in all_change_ids]

            # If the model placed a historical ID into supporting_evidence_ids, migrate it to historical_reference_ids
            for eid in cand.supporting_evidence_ids:
                if eid in all_historical_ids and eid not in valid_historical_refs:
                    valid_historical_refs.append(eid)
                elif eid in all_change_ids and eid not in valid_change_refs:
                    valid_change_refs.append(eid)

            # Invariant: If model did NOT supply valid supporting IDs from current evidence,
            # supporting_evidence_ids remains empty. Never fabricate artificial groundedness.

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
                    historical_reference_ids=valid_historical_refs,
                    related_change_ids=valid_change_refs,
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
        service_name = resolve_service_from_state(state, default="demo-service")
        top_hist_ids = [str(similar_incidents[0].incident_id)] if similar_incidents else []
        top_change_ids = [candidate_causal_changes[0].id] if candidate_causal_changes else []

        pool_matching_ids = [
            e.id
            for e in evidence_list
            if "pool" in e.summary.lower()
            or "db_pool" in e.summary.lower()
            or "connection" in e.summary.lower()
            or "exhausted" in e.summary.lower()
        ]

        if pool_matching_ids:
            # Check if there is a correlated config change reducing DB_POOL_SIZE
            causal_desc = "Service connection pool reached max capacity leading to queue timeouts and 500 errors."
            if candidate_causal_changes:
                first_ch = candidate_causal_changes[0]
                causal_desc += f" Triggered by {first_ch.title} ({first_ch.id})."

            hypotheses.append(
                Hypothesis(
                    id=str(uuid4()),
                    title="Database Connection Pool Exhaustion",
                    description=causal_desc,
                    affected_component=service_name,
                    confidence_score=0.90 if candidate_causal_changes else 0.85,
                    status=HypothesisStatus.PROPOSED,
                    supporting_evidence_ids=pool_matching_ids,
                    historical_reference_ids=top_hist_ids,
                    related_change_ids=top_change_ids,
                    reasoning_summary="Error logs indicate connection pool exhaustion matching recent configuration change."
                    if candidate_causal_changes
                    else "Error logs explicitly indicate connection pool exhaustion during transactions.",
                    created_at=now,
                )
            )
        else:
            error_matching_ids = [
                e.id
                for e in evidence_list
                if any(
                    k in e.summary.lower()
                    for k in (
                        "500",
                        "502",
                        "503",
                        "5xx",
                        "error",
                        "server error",
                        "exception",
                        "failed",
                    )
                )
            ]
            hypotheses.append(
                Hypothesis(
                    id=str(uuid4()),
                    title="Elevated Application Error Rate",
                    description="Incoming requests to service are encountering 5xx server exceptions.",
                    affected_component=service_name,
                    confidence_score=0.75,
                    status=HypothesisStatus.PROPOSED,
                    supporting_evidence_ids=error_matching_ids,
                    historical_reference_ids=top_hist_ids,
                    related_change_ids=top_change_ids,
                    reasoning_summary="Metrics show non-zero 5xx error rate on HTTP endpoints.",
                    created_at=now,
                )
            )

    logger.info(
        "hypotheses_generated",
        incident_id=incident_id,
        count=len(hypotheses),
        top_title=hypotheses[0].title if hypotheses else None,
        top_historical_refs=hypotheses[0].historical_reference_ids if hypotheses else [],
        top_related_changes=hypotheses[0].related_change_ids if hypotheses else [],
    )

    return {
        "hypotheses": hypotheses,
        "errors": node_errors,
    }
