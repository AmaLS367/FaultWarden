"""Hypothesis verification node: evaluates candidates against evidence and determines root cause."""

from datetime import UTC, datetime
from typing import Any

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.llm.provider import get_llm_provider, wrap_untrusted_telemetry
from faultwarden.schemas.hypothesis import (
    Hypothesis,
    HypothesisStatus,
    HypothesisVerificationResponse,
    RootCauseAnalysis,
)

logger = get_logger("faultwarden.graph.nodes.verify")


# --- Hypothesis Verification Logic ---
async def verify_hypothesis_node(
    state: IncidentInvestigationState,
) -> dict[str, Any]:
    """Test candidate hypotheses against accumulated evidence and promote verified root cause."""
    incident_id = state.get("incident_id", "unknown")
    hypotheses = state.get("hypotheses", [])
    evidence_list = state.get("evidence", [])
    iteration = state.get("iteration_count", 1)

    settings = get_settings()
    confidence_threshold = settings.investigation.confidence_threshold
    max_iterations = settings.investigation.max_iterations

    logger.info(
        "hypothesis_verification_started",
        incident_id=incident_id,
        candidate_count=len(hypotheses),
        iteration=iteration,
    )

    if not hypotheses:
        logger.warning("no_hypotheses_available_for_verification", incident_id=incident_id)
        return {
            "selected_hypothesis": None,
            "root_cause": None,
            "missing_evidence_queries": [],
        }

    best_candidate: Hypothesis = max(hypotheses, key=lambda h: h.confidence_score)

    # Prepare evidence summary for LLM verification
    evidence_text = "\n".join(
        f"- [{item.id}] ({item.evidence_type.value}) {item.summary}" for item in evidence_list
    )
    protected_evidence = wrap_untrusted_telemetry(evidence_text)

    prompt = (
        "Evaluate the following candidate hypothesis against all accumulated evidence.\n\n"
        f"Candidate Hypothesis:\n"
        f"Title: {best_candidate.title}\n"
        f"Description: {best_candidate.description}\n"
        f"Affected Component: {best_candidate.affected_component}\n"
        f"Current Confidence: {best_candidate.confidence_score}\n\n"
        f"Evidence Inventory:\n{protected_evidence}\n\n"
        "Decision Criteria:\n"
        "1. Is the candidate strongly supported by direct evidence (e.g. error logs, metric spikes)?\n"
        f"2. Does confidence meet or exceed the threshold {confidence_threshold}?\n"
        "3. If evidence is insufficient, list 1-2 specific PromQL or LogQL queries needed."
    )

    llm = get_llm_provider()
    missing_queries: list[str] = []
    evaluated_confidence = best_candidate.confidence_score
    is_verified = False
    eval_reasoning = ""

    try:
        ver_resp: HypothesisVerificationResponse = await llm.generate_structured(
            prompt=prompt,
            schema=HypothesisVerificationResponse,
            system_prompt="You are a strict SRE Incident Verification Evaluator.",
        )
        evaluated_confidence = ver_resp.confidence_score
        is_verified = ver_resp.is_verified
        eval_reasoning = ver_resp.reasoning
        missing_queries = ver_resp.additional_queries_needed
    except Exception as exc:
        logger.warning("llm_verification_evaluation_failed", error=str(exc))
        # Fallback deterministic evaluation based on candidate confidence score
        if best_candidate.confidence_score >= confidence_threshold:
            is_verified = True
            evaluated_confidence = best_candidate.confidence_score
            eval_reasoning = "Candidate confidence meets threshold based on direct evidence."
        else:
            is_verified = False
            eval_reasoning = "Confidence below verification threshold; additional evidence needed."

    best_candidate.confidence_score = evaluated_confidence

    # Application code owns the transition policy
    root_cause: RootCauseAnalysis | None = None

    if (
        is_verified and evaluated_confidence >= confidence_threshold
    ) or iteration >= max_iterations:
        best_candidate.status = HypothesisStatus.VERIFIED
        now = datetime.now(UTC)
        classification = state.get("classification")
        category_name = classification.category.value if classification is not None else "UNKNOWN"

        root_cause = RootCauseAnalysis(
            primary_hypothesis_id=best_candidate.id,
            summary=f"Root cause verified: {best_candidate.title}. {best_candidate.description}",
            root_cause_category=category_name,
            culprit_service=best_candidate.affected_component,
            contributing_factors=[
                best_candidate.reasoning_summary or eval_reasoning,
                f"Evaluation score: {evaluated_confidence:.2f} (threshold: {confidence_threshold})",
            ],
            supporting_evidence_ids=best_candidate.supporting_evidence_ids,
            technical_details={
                "verified_in_iteration": iteration,
                "confidence": evaluated_confidence,
            },
            confidence=evaluated_confidence,
            identified_at=now,
        )

        logger.info(
            "root_cause_identified",
            incident_id=incident_id,
            hypothesis_title=best_candidate.title,
            confidence=evaluated_confidence,
            iteration=iteration,
        )

        return {
            "selected_hypothesis": best_candidate,
            "root_cause": root_cause,
            "investigation_status": "ROOT_CAUSE_IDENTIFIED",
            "missing_evidence_queries": [],
        }

    # Request missing telemetry when confidence remains below verification threshold
    best_candidate.status = HypothesisStatus.TESTING
    logger.info(
        "additional_evidence_requested",
        incident_id=incident_id,
        current_confidence=evaluated_confidence,
        missing_queries_count=len(missing_queries),
        iteration=iteration,
    )

    return {
        "selected_hypothesis": best_candidate,
        "root_cause": None,
        "missing_evidence_queries": missing_queries or ["sum(rate(http_requests_total[1m]))"],
    }
