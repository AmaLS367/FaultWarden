"""Evidence and Change correlation node: synthesizes multi-source telemetry and evaluates candidate causal changes."""

from datetime import UTC, datetime
from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import resolve_service_from_state
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.change import (
    CausalChangeType,
    ChangeCorrelation,
    OperationalChange,
)
from faultwarden.schemas.evidence import EvidenceItem

logger = get_logger("faultwarden.graph.nodes.correlate")

# Domain keyword clusters for deterministic symptom-to-change alignment
_SYMPTOM_CLUSTERS: dict[str, set[str]] = {
    "db_pool": {
        "db_pool",
        "pool",
        "connection",
        "exhausted",
        "max_connections",
        "pool_size",
        "database",
        "postgres",
        "psycopg",
        "asyncpg",
        "acquire",
        "queue",
    },
    "timeout": {
        "timeout",
        "timed_out",
        "deadline",
        "latency",
        "slow",
        "504",
        "gateway",
        "response_time",
    },
    "memory": {
        "memory",
        "oom",
        "heap",
        "out of memory",
        "killed",
        "ram",
        "leak",
    },
    "error_rate": {
        "500",
        "502",
        "503",
        "server error",
        "internal server error",
        "exception",
        "traceback",
        "failed",
        "error",
    },
    "concurrency": {
        "concurrency",
        "workers",
        "threads",
        "rate_limit",
        "throttled",
        "capacity",
    },
}


def _calculate_temporal_score(change_ts: datetime, incident_ts: datetime) -> float:
    """Calculate temporal proximity score with strict decay and post-incident penalty."""
    # Ensure both datetimes are timezone-aware or naive matching
    c_ts = change_ts if change_ts.tzinfo is not None else change_ts.replace(tzinfo=UTC)
    i_ts = incident_ts if incident_ts.tzinfo is not None else incident_ts.replace(tzinfo=UTC)

    delta_seconds = (i_ts - c_ts).total_seconds()

    if delta_seconds < 0:
        # Change occurred after incident detection
        abs_after = abs(delta_seconds)
        if abs_after <= 60:
            return 0.2
        return 0.0

    if delta_seconds <= 300:  # 0 to 5 minutes before
        return 1.0 - (delta_seconds / 300.0) * 0.1  # 0.9 to 1.0
    if delta_seconds <= 1800:  # 5 to 30 minutes before
        return 0.9 - ((delta_seconds - 300) / 1500.0) * 0.3  # 0.6 to 0.9
    if delta_seconds <= 7200:  # 30 minutes to 2 hours before
        return 0.6 - ((delta_seconds - 1800) / 5400.0) * 0.4  # 0.2 to 0.6
    return 0.1  # > 2 hours before


def _assess_symptom_match(
    change: OperationalChange,
    evidence_texts: list[tuple[str, str]],
) -> tuple[bool, list[str], CausalChangeType]:
    """Check whether a change's title, diffs, or config keys semantically align with evidence symptoms."""
    change_tokens: set[str] = set()

    for word in (change.title + " " + (change.description or "")).lower().split():
        clean = word.strip(".,;:()[]{}'\"-_/\\")
        if clean:
            change_tokens.add(clean)

    for cfg in change.config_changes:
        for part in cfg.key.lower().replace("_", " ").split():
            change_tokens.add(part)
        if cfg.key.upper() in ("DB_POOL_SIZE", "POOL_SIZE", "MAX_CONNECTIONS"):
            change_tokens.update(["db_pool", "pool", "connection", "database"])

    for f in change.files_changed:
        for part in f.lower().replace("/", " ").replace(".", " ").split():
            change_tokens.add(part)

    matching_evidence_ids: list[str] = []
    matched_clusters: set[str] = set()

    for eid, summary in evidence_texts:
        sum_lower = summary.lower()

        for cluster_name, keywords in _SYMPTOM_CLUSTERS.items():
            cluster_in_change = bool(change_tokens & keywords)
            cluster_in_evidence = any(k in sum_lower for k in keywords)

            if cluster_in_change and cluster_in_evidence:
                matched_clusters.add(cluster_name)
                if eid not in matching_evidence_ids:
                    matching_evidence_ids.append(eid)

    symptom_match = len(matched_clusters) > 0

    # Classify causal category
    if any(
        cfg.key.upper()
        in ("DB_POOL_SIZE", "POOL_SIZE", "MAX_CONNECTIONS", "MEMORY_LIMIT", "CPU_LIMIT")
        for cfg in change.config_changes
    ):
        causal_cat = CausalChangeType.RESOURCE_LIMIT_CHANGE
    elif change.config_changes:
        causal_cat = CausalChangeType.CONFIG_REGRESSION
    elif change.files_changed and any(
        f.endswith((".py", ".js", ".go", ".rs", ".java")) for f in change.files_changed
    ):
        causal_cat = CausalChangeType.CODE_REGRESSION
    elif change.change_type == "DEPLOYMENT":
        causal_cat = (
            CausalChangeType.CONFIG_REGRESSION
            if change.config_changes
            else CausalChangeType.CODE_REGRESSION
        )
    elif symptom_match:
        causal_cat = CausalChangeType.CODE_REGRESSION
    else:
        causal_cat = CausalChangeType.UNRELATED_CHANGE

    return symptom_match, matching_evidence_ids, causal_cat


# --- Single Change Correlation Helper ---
def correlate_change_with_incident(
    change: OperationalChange,
    incident_service: str,
    incident_start_time: datetime,
    evidence: list[EvidenceItem],
    correlation_threshold: float = 0.60,
) -> ChangeCorrelation:
    """Correlate an individual operational change against incident service and telemetry evidence."""
    evidence_texts = [
        (
            e.id,
            f"{e.summary} {e.evidence_type.value if hasattr(e.evidence_type, 'value') else str(e.evidence_type)} {e.source}",
        )
        for e in evidence
    ]
    component_match = change.service.lower() == incident_service.lower()
    temporal_score = _calculate_temporal_score(change.timestamp, incident_start_time)
    symptom_match, evidence_links, causal_cat = _assess_symptom_match(change, evidence_texts)

    if not component_match:
        relevance_score = 0.0
        explanation = f"Change service '{change.service}' does not match incident service '{incident_service}'."
        is_candidate = False
    else:
        base_score = (
            (0.35 * temporal_score)
            + (0.45 * (1.0 if symptom_match else 0.0))
            + (0.20 * (1.0 if evidence_links else 0.0))
        )
        if not symptom_match:
            relevance_score = min(base_score, 0.35)
            explanation = (
                f"Change '{change.title}' occurred close in time (temporal: {temporal_score:.2f}) "
                "but diff/parameters do not match failure symptoms."
            )
            is_candidate = False
        else:
            relevance_score = round(base_score, 2)
            is_candidate = (
                relevance_score >= correlation_threshold
                and temporal_score >= 0.3
                and component_match
            )
            explanation = (
                f"Change '{change.title}' is strongly correlated (relevance: {relevance_score:.2f}, "
                f"temporal: {temporal_score:.2f}, matching {len(evidence_links)} evidence item(s))."
            )

    return ChangeCorrelation(
        change_id=change.id,
        temporal_score=round(temporal_score, 2),
        component_match=component_match,
        symptom_match=symptom_match,
        evidence_links=evidence_links,
        contradicting_evidence_ids=[],
        relevance_score=relevance_score,
        causal_category=causal_cat,
        is_causal_candidate=is_candidate,
        explanation=explanation,
    )


# --- Evidence Correlation ---
async def correlate_evidence_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    """Summarize accumulated telemetry and perform multi-factor causal change correlation.

    Strict Causality Invariant:
    Temporal proximity alone cannot establish causation. A recent deployment or config
    change only becomes a candidate causal factor if:
    1. Service / component matches;
    2. Change occurred before incident onset;
    3. Change diff / parameters semantically align with observed telemetry evidence;
    4. Multi-factor relevance score meets or exceeds the correlation threshold.
    """
    incident_id = state.get("incident_id", "unknown")
    evidence_list = state.get("evidence", [])
    recent_changes = state.get("recent_changes", [])
    settings = get_settings()
    correlation_threshold = settings.change.correlation_threshold

    service_name = resolve_service_from_state(state, default="demo-service")

    logger.info(
        "evidence_correlation_started",
        incident_id=incident_id,
        evidence_count=len(evidence_list),
        changes_count=len(recent_changes),
    )

    # Reference timestamp for incident
    alert_info = state.get("alert", {})
    alerts_list = alert_info.get("alerts", [])
    incident_ts: datetime = datetime.now(UTC)
    if alerts_list and isinstance(alerts_list, list) and isinstance(alerts_list[0], dict):
        starts_at_str = alerts_list[0].get("startsAt")
        if starts_at_str:
            try:
                norm_str = str(starts_at_str)
                if norm_str.endswith("Z"):
                    norm_str = norm_str[:-1] + "+00:00"
                incident_ts = datetime.fromisoformat(norm_str)
            except Exception:
                pass

    correlations: list[ChangeCorrelation] = []
    candidate_causal_changes: list[OperationalChange] = []

    for change in recent_changes:
        corr = correlate_change_with_incident(
            change=change,
            incident_service=service_name,
            incident_start_time=incident_ts,
            evidence=evidence_list,
            correlation_threshold=correlation_threshold,
        )
        correlations.append(corr)
        if corr.is_causal_candidate:
            candidate_causal_changes.append(change)

    metric_count = sum(1 for e in evidence_list if e.evidence_type == "METRIC")
    log_count = sum(1 for e in evidence_list if e.evidence_type == "LOG")
    alert_count = sum(1 for e in evidence_list if e.evidence_type == "ALERT")

    correlation_summary = (
        f"Correlated {len(evidence_list)} evidence items ({alert_count} alert, {metric_count} metric, {log_count} log) "
        f"with {len(recent_changes)} recent change(s). Found {len(candidate_causal_changes)} candidate causal change(s)."
    )

    logger.info(
        "evidence_correlation_completed",
        incident_id=incident_id,
        total_evidence=len(evidence_list),
        total_changes=len(recent_changes),
        candidate_causal_changes_count=len(candidate_causal_changes),
        summary=correlation_summary,
    )

    return {
        "summary": correlation_summary,
        "change_correlations": correlations,
        "candidate_causal_changes": candidate_causal_changes,
    }
