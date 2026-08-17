"""Unit tests for change correlation and negative correlation causality invariants."""

from datetime import UTC, datetime

from faultwarden.graph.nodes.correlate import correlate_change_with_incident
from faultwarden.schemas.change import (
    CausalChangeType,
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)
from faultwarden.schemas.evidence import EvidenceItem, EvidenceType


def test_correlated_change_positive_causation() -> None:
    """Test matching service + pre-incident + matching symptom cluster produces high correlation and marks causal candidate."""
    incident_start = datetime(2026, 8, 17, 5, 10, 0, tzinfo=UTC)
    change_time = datetime(2026, 8, 17, 5, 0, 0, tzinfo=UTC)  # 10 minutes before incident

    change = OperationalChange(
        id="deploy-002",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy v1.0.1 with DB_POOL_SIZE reduced",
        timestamp=change_time,
        config_changes=[
            ConfigurationChange(
                key="DB_POOL_SIZE",
                old_value="20",
                new_value="5",
                component="database",
            )
        ],
    )

    evidence = [
        EvidenceItem(
            id="ev-log-1",
            evidence_type=EvidenceType.LOG,
            summary="[DB_POOL_EXHAUSTED] Database connection pool exhausted: active_connections=5/5 timeout=5000ms",
            source="loki",
            timestamp=incident_start,
        ),
        EvidenceItem(
            id="ev-metric-1",
            evidence_type=EvidenceType.METRIC,
            summary="http_requests_total 500 error rate spiked to 95%",
            source="prometheus",
            timestamp=incident_start,
        ),
    ]

    corr = correlate_change_with_incident(
        change=change,
        incident_service="demo-service",
        incident_start_time=incident_start,
        evidence=evidence,
        correlation_threshold=0.60,
    )

    assert corr.component_match is True
    assert corr.symptom_match is True
    assert corr.temporal_score >= 0.70
    assert corr.relevance_score >= 0.70
    assert corr.is_causal_candidate is True
    assert corr.causal_category == CausalChangeType.RESOURCE_LIMIT_CHANGE
    assert "ev-log-1" in corr.evidence_links


def test_invariant_unrelated_service_not_causal_candidate() -> None:
    """Invariant test: Deployment occurred 2 min before incident, but on an UNRELATED service -> NOT causal candidate."""
    incident_start = datetime(2026, 8, 17, 5, 10, 0, tzinfo=UTC)
    change_time = datetime(2026, 8, 17, 5, 8, 0, tzinfo=UTC)  # 2 mins before incident

    # Change happened on 'auth-service', but incident is on 'payment-service'
    change = OperationalChange(
        id="deploy-auth-99",
        source="deployment",
        service="auth-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy auth-service v2.1",
        timestamp=change_time,
        config_changes=[
            ConfigurationChange(
                key="JWT_EXPIRY",
                old_value="3600",
                new_value="7200",
            )
        ],
    )

    evidence = [
        EvidenceItem(
            id="ev-1",
            evidence_type=EvidenceType.LOG,
            summary="payment-service database connection pool exhausted",
            source="loki",
            timestamp=incident_start,
        )
    ]

    corr = correlate_change_with_incident(
        change=change,
        incident_service="payment-service",
        incident_start_time=incident_start,
        evidence=evidence,
        correlation_threshold=0.60,
    )

    assert corr.component_match is False
    assert corr.is_causal_candidate is False
    assert corr.relevance_score < 0.60


def test_invariant_temporal_proximity_alone_not_causation() -> None:
    """Invariant test: Deployment occurred on same service 1 min before, but unrelated symptoms (e.g. css tweak) -> NOT causal candidate."""
    incident_start = datetime(2026, 8, 17, 5, 10, 0, tzinfo=UTC)
    change_time = datetime(2026, 8, 17, 5, 9, 0, tzinfo=UTC)  # 1 min before incident!

    # Same service, but changed UI banner styling / static assets
    change = OperationalChange(
        id="deploy-ui-banner",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Update holiday banner styling and colors",
        files_changed=["static/css/banner.css", "templates/header.html"],
        timestamp=change_time,
        config_changes=[],
    )

    evidence = [
        EvidenceItem(
            id="ev-1",
            evidence_type=EvidenceType.LOG,
            summary="[DB_POOL_EXHAUSTED] Database connection pool exhausted: active_connections=20/20",
            source="loki",
            timestamp=incident_start,
        )
    ]

    corr = correlate_change_with_incident(
        change=change,
        incident_service="demo-service",
        incident_start_time=incident_start,
        evidence=evidence,
        correlation_threshold=0.60,
    )

    assert corr.component_match is True
    # Symptom match MUST be false because css/header changes do not match database connection pool keywords
    assert corr.symptom_match is False
    # Relevance score MUST be capped at 0.35 so time proximity alone cannot qualify it
    assert corr.relevance_score <= 0.35
    assert corr.is_causal_candidate is False


def test_invariant_post_incident_change_not_causal_candidate() -> None:
    """Invariant test: Change happened AFTER incident started -> NOT causal candidate."""
    incident_start = datetime(2026, 8, 17, 5, 10, 0, tzinfo=UTC)
    change_time = datetime(2026, 8, 17, 5, 20, 0, tzinfo=UTC)  # 10 minutes AFTER incident!

    change = OperationalChange(
        id="deploy-hotfix",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Hotfix attempt pool size",
        timestamp=change_time,
        config_changes=[
            ConfigurationChange(
                key="DB_POOL_SIZE",
                old_value="5",
                new_value="50",
            )
        ],
    )

    evidence = [
        EvidenceItem(
            id="ev-1",
            evidence_type=EvidenceType.LOG,
            summary="[DB_POOL_EXHAUSTED] Database connection pool exhausted",
            source="loki",
            timestamp=incident_start,
        )
    ]

    corr = correlate_change_with_incident(
        change=change,
        incident_service="demo-service",
        incident_start_time=incident_start,
        evidence=evidence,
        correlation_threshold=0.60,
    )

    assert corr.temporal_score <= 0.20
    assert corr.is_causal_candidate is False
