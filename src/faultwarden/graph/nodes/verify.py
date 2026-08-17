"""Hypothesis verification node: evaluates candidates against evidence and determines root cause."""

from datetime import UTC, datetime
from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.causality import verify_causal_change_association
from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import get_llm_provider_from_config
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.integrations.llm.provider import wrap_untrusted_telemetry
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
    config: RunnableConfig | None = None,
) -> dict[str, Any]:
    """Test candidate hypotheses against accumulated evidence and promote verified root cause."""
    incident_id = state.get("incident_id", "unknown")
    hypotheses = state.get("hypotheses", [])
    evidence_list = state.get("evidence", [])
    iteration = state.get("iteration_count", 1)

    settings = get_settings()
    confidence_threshold = settings.investigation.confidence_threshold
    max_iterations = settings.investigation.max_iterations
    correlation_threshold = settings.change.correlation_threshold

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

    llm = get_llm_provider_from_config(config)
    missing_queries: list[str] = []
    evaluated_confidence = best_candidate.confidence_score
    is_verified = False
    eval_reasoning = ""
    node_errors: list[str] = []

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
        node_errors.append(f"verify_hypothesis: LLM verification failed, using fallback: {exc}")
        # Fallback deterministic evaluation based on candidate confidence score
        if best_candidate.confidence_score >= confidence_threshold:
            is_verified = True
            evaluated_confidence = best_candidate.confidence_score
            eval_reasoning = "Candidate confidence meets threshold based on direct evidence."
        else:
            is_verified = False
            eval_reasoning = "Confidence below verification threshold; additional evidence needed."

    def _with_updated_candidate(
        new_status: HypothesisStatus,
    ) -> tuple[Hypothesis, list[Hypothesis]]:
        """Functionally update the candidate (never mutate a Hypothesis living in state)."""
        updated = best_candidate.model_copy(
            update={"confidence_score": evaluated_confidence, "status": new_status}
        )
        updated_list = [updated if h.id == best_candidate.id else h for h in hypotheses]
        return updated, updated_list

    # Application code owns the transition policy
    valid_evidence_ids = {e.id for e in evidence_list}
    has_valid_supporting_evidence = any(
        eid in valid_evidence_ids for eid in best_candidate.supporting_evidence_ids
    )

    # Invariant: A hypothesis CANNOT be verified without at least one direct current evidence item
    if (
        is_verified
        and evaluated_confidence >= confidence_threshold
        and has_valid_supporting_evidence
    ):
        # Filter candidate's supporting evidence strictly against current evidence inventory
        sanitized_supporting_ids = [
            eid for eid in best_candidate.supporting_evidence_ids if eid in valid_evidence_ids
        ]

        updated_candidate, updated_hypotheses = _with_updated_candidate(HypothesisStatus.VERIFIED)
        # Ensure the candidate in state has sanitized supporting evidence IDs
        updated_candidate = updated_candidate.model_copy(
            update={"supporting_evidence_ids": sanitized_supporting_ids}
        )
        updated_hypotheses = [
            updated_candidate if h.id == best_candidate.id else h for h in updated_hypotheses
        ]

        # Check and verify causal change associations through deterministic promotion gate
        recent_changes = state.get("recent_changes", [])
        change_correlations = state.get("change_correlations", [])
        change_map = {ch.id: ch for ch in recent_changes}
        corr_map = {corr.change_id: corr for corr in change_correlations}

        causal_changes: list[Any] = []
        causal_change_ids: list[str] = []
        causal_change_summary: str | None = None
        selected_causal_change = None
        causal_change_type_val: str | None = None

        for cid in updated_candidate.related_change_ids:
            if cid in change_map:
                ch = change_map[cid]
                corr = corr_map.get(cid)
                if verify_causal_change_association(
                    hypothesis=updated_candidate,
                    change=ch,
                    correlation=corr,
                    current_evidence_ids=valid_evidence_ids,
                    correlation_threshold=correlation_threshold,
                ):
                    causal_changes.append(ch)
                    causal_change_ids.append(ch.id)
                    if selected_causal_change is None:
                        selected_causal_change = ch
                        if corr is not None and hasattr(corr.causal_category, "value"):
                            causal_change_type_val = corr.causal_category.value
                        elif hasattr(ch.change_type, "value"):
                            causal_change_type_val = ch.change_type.value

        if selected_causal_change is not None:
            config_diffs = []
            for cfg in selected_causal_change.config_changes:
                config_diffs.append(f"{cfg.key}: {cfg.old_value} -> {cfg.new_value}")
            diff_str = f" (Diff: {', '.join(config_diffs)})" if config_diffs else ""
            causal_change_summary = (
                f"{selected_causal_change.title} [{selected_causal_change.id}]{diff_str}"
            )

        factors = [
            updated_candidate.reasoning_summary or eval_reasoning,
            f"Evaluation score: {evaluated_confidence:.2f} (threshold: {confidence_threshold})",
        ]
        if causal_change_summary:
            factors.append(f"Correlated causal change: {causal_change_summary}")

        now = datetime.now(UTC)
        classification = state.get("classification")
        category_name = classification.category.value if classification is not None else "UNKNOWN"

        tech_details: dict[str, Any] = {
            "verified_in_iteration": iteration,
            "confidence": evaluated_confidence,
            "causal_change_ids": causal_change_ids,
        }
        if causal_change_type_val is not None:
            tech_details["causal_change_type"] = causal_change_type_val

        root_cause = RootCauseAnalysis(
            primary_hypothesis_id=updated_candidate.id,
            summary=f"Root cause verified: {updated_candidate.title}. {updated_candidate.description}",
            root_cause_category=category_name,
            culprit_service=updated_candidate.affected_component,
            contributing_factors=factors,
            supporting_evidence_ids=sanitized_supporting_ids,
            causal_change_ids=causal_change_ids,
            causal_change_summary=causal_change_summary,
            technical_details=tech_details,
            confidence=evaluated_confidence,
            identified_at=now,
        )

        logger.info(
            "root_cause_identified",
            incident_id=incident_id,
            hypothesis_title=updated_candidate.title,
            confidence=evaluated_confidence,
            causal_changes=causal_change_ids,
            iteration=iteration,
        )

        return {
            "hypotheses": updated_hypotheses,
            "selected_hypothesis": updated_candidate,
            "selected_causal_change": selected_causal_change,
            "root_cause": root_cause,
            "investigation_status": "ROOT_CAUSE_IDENTIFIED",
            "missing_evidence_queries": [],
            "errors": node_errors,
        }

    # Not verified: at the last allowed iteration, stop looping without fabricating a root
    # cause (should_continue_investigation already routes to propose_remediation once
    # max_iterations is reached, regardless of root_cause). Otherwise request more telemetry.
    at_max_iterations = iteration >= max_iterations
    final_status = HypothesisStatus.INCONCLUSIVE if at_max_iterations else HypothesisStatus.TESTING
    updated_candidate, updated_hypotheses = _with_updated_candidate(final_status)

    logger.info(
        "investigation_inconclusive_at_max_iterations"
        if at_max_iterations
        else "additional_evidence_requested",
        incident_id=incident_id,
        current_confidence=evaluated_confidence,
        missing_queries_count=len(missing_queries),
        iteration=iteration,
    )

    return {
        "hypotheses": updated_hypotheses,
        "selected_hypothesis": updated_candidate,
        "root_cause": None,
        "missing_evidence_queries": []
        if at_max_iterations
        else (missing_queries or ["sum(rate(http_requests_total[1m]))"]),
        "errors": node_errors,
    }
