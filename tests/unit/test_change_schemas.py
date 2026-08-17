"""Unit tests for Change Intelligence domain schemas, secret redaction, and prompt sanitization."""

from datetime import UTC, datetime

from faultwarden.schemas.change import (
    ChangeCorrelation,
    ChangeType,
    ConfigurationChange,
    DeploymentRecord,
    OperationalChange,
    is_sensitive_key,
    sanitize_change_for_prompt,
)


def test_is_sensitive_key() -> None:
    """Test deterministic identification of sensitive credentials/keys."""
    assert is_sensitive_key("DATABASE_PASSWORD") is True
    assert is_sensitive_key("API_KEY") is True
    assert is_sensitive_key("JWT_SECRET") is True
    assert is_sensitive_key("AUTH_TOKEN") is True
    assert is_sensitive_key("STRIPE_PRIVATE_KEY") is True
    assert is_sensitive_key("CERTIFICATE_KEY") is True

    assert is_sensitive_key("DB_POOL_SIZE") is False
    assert is_sensitive_key("TIMEOUT_MS") is False
    assert is_sensitive_key("MAX_WORKERS") is False
    assert is_sensitive_key("LOG_LEVEL") is False


def test_sanitize_change_for_prompt_masks_secrets() -> None:
    """Test secret redaction in ConfigurationChange objects and prompt sanitization."""
    now = datetime.now(UTC)
    change = OperationalChange(
        id="dep-123",
        source="deployment",
        service="payment-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Release 2.0 with new auth token",
        timestamp=now,
        config_changes=[
            ConfigurationChange(
                key="DB_PASSWORD",
                old_value="old_secret_12345",
                new_value="new_secret_67890",
            ),
            ConfigurationChange(
                key="DB_POOL_SIZE",
                old_value="20",
                new_value="5",
            ),
        ],
    )

    prompt_str = sanitize_change_for_prompt(change)
    assert "[REDACTED]" in prompt_str
    assert "old_secret_12345" not in prompt_str
    assert "new_secret_67890" not in prompt_str
    assert "DB_POOL_SIZE: 20 -> 5" in prompt_str


def test_operational_change_schema_defaults() -> None:
    """Test OperationalChange schema defaults and validation."""
    now = datetime.now(UTC)
    change = OperationalChange(
        id="git-commit-1",
        source="git",
        service="demo-service",
        change_type=ChangeType.GIT_COMMIT,
        title="Fix database retry logic",
        timestamp=now,
    )
    assert change.id == "git-commit-1"
    assert change.service == "demo-service"
    assert change.change_type == ChangeType.GIT_COMMIT
    assert change.files_changed == []
    assert change.config_changes == []
    assert change.metadata == {}


def test_deployment_record_schema() -> None:
    """Test DeploymentRecord schema fields."""
    now = datetime.now(UTC)
    record = DeploymentRecord(
        id="deploy-99",
        service="checkout-service",
        version="v1.4.2",
        environment="production",
        commit_sha="a1b2c3d4",
        started_at=now,
        status="SUCCESS",
        config_changes=[
            ConfigurationChange(
                key="TIMEOUT_MS",
                old_value="30000",
                new_value="5000",
            )
        ],
    )
    assert record.id == "deploy-99"
    assert record.version == "v1.4.2"
    assert record.environment == "production"
    assert len(record.config_changes) == 1


def test_change_correlation_schema_validation() -> None:
    """Test ChangeCorrelation score bounds validation."""
    corr = ChangeCorrelation(
        change_id="dep-1",
        relevance_score=0.85,
        temporal_score=0.90,
        component_match=True,
        symptom_match=True,
        is_causal_candidate=True,
        explanation="DB_POOL_SIZE decreased right before pool exhaustion error",
    )
    assert corr.relevance_score == 0.85
    assert corr.is_causal_candidate is True
