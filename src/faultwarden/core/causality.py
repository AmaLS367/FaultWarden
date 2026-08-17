"""Deterministic causal promotion policy engine for FaultWarden Change Intelligence."""

from faultwarden.core.logging import get_logger
from faultwarden.schemas.change import ChangeCorrelation, OperationalChange
from faultwarden.schemas.hypothesis import Hypothesis

logger = get_logger("faultwarden.core.causality")


# --- Causal Verification Gate ---
def verify_causal_change_association(
    hypothesis: Hypothesis,
    change: OperationalChange,
    correlation: ChangeCorrelation | None,
    current_evidence_ids: set[str],
    correlation_threshold: float = 0.60,
) -> bool:
    """Deterministically determine whether an operational change qualifies as a VERIFIED causal change.

    A change cannot become a verified causal change merely because:
    - it occurred recently;
    - it belongs to the same service;
    - the LLM referenced it in related_change_ids or supporting_evidence_ids;
    - the containing hypothesis was otherwise verified.

    To be promoted to a verified causal change, ALL of the following 10 requirements MUST pass:
    1. The change ID is present and valid;
    2. A corresponding ChangeCorrelation object exists for the change;
    3. ChangeCorrelation.is_causal_candidate is strictly True;
    4. Component match is True and change.service matches hypothesis.affected_component;
    5. Symptom match is strictly True (change diff/parameters match failure symptoms);
    6. relevance_score meets or exceeds the correlation threshold;
    7. evidence_links contains at least one current evidence ID;
    8. At least one linked evidence ID currently exists in current_evidence_ids;
    9. The change occurred before incident onset according to correlation semantics (temporal_score >= 0.30);
    10. The hypothesis explicitly references the change via related_change_ids.
    """
    # 1. Basic validation
    if not change or not change.id:
        logger.debug("causal_gate_rejected", reason="Missing or invalid change object")
        return False

    # 2. Correlation presence
    if correlation is None:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="No ChangeCorrelation record found for change",
        )
        return False

    if correlation.change_id != change.id:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason=f"Correlation change_id mismatch ({correlation.change_id} != {change.id})",
        )
        return False

    # 3. Candidate flag
    if not correlation.is_causal_candidate:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="ChangeCorrelation.is_causal_candidate is False",
        )
        return False

    # 4. Component match (both in correlation and against hypothesis affected component)
    if not correlation.component_match:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="ChangeCorrelation.component_match is False",
        )
        return False

    if change.service.lower() != hypothesis.affected_component.lower():
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason=f"Change service '{change.service}' does not match hypothesis component '{hypothesis.affected_component}'",
        )
        return False

    # 5. Symptom match
    if not correlation.symptom_match:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="ChangeCorrelation.symptom_match is False (no symptom alignment)",
        )
        return False

    # 6. Relevance score threshold
    if correlation.relevance_score < correlation_threshold:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason=f"Relevance score {correlation.relevance_score:.2f} below threshold {correlation_threshold:.2f}",
        )
        return False

    # 7 & 8. Current evidence linkage
    if not correlation.evidence_links:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="ChangeCorrelation has empty evidence_links",
        )
        return False

    active_linked_evidence = [
        eid for eid in correlation.evidence_links if eid in current_evidence_ids
    ]
    if not active_linked_evidence:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="None of the correlation's evidence_links exist in current active evidence inventory",
        )
        return False

    # 9. Temporal ordering (temporal_score must indicate pre-incident occurrence)
    if correlation.temporal_score < 0.30:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason=f"Temporal score {correlation.temporal_score:.2f} is too low or indicates post-incident change",
        )
        return False

    # 10. Hypothesis explicit reference
    if change.id not in hypothesis.related_change_ids:
        logger.debug(
            "causal_gate_rejected",
            change_id=change.id,
            reason="Hypothesis does not explicitly reference change in related_change_ids",
        )
        return False

    logger.info(
        "causal_gate_verified",
        change_id=change.id,
        hypothesis_id=hypothesis.id,
        relevance_score=correlation.relevance_score,
        evidence_links_count=len(active_linked_evidence),
    )
    return True
