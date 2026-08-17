"""Domain schemas and models for Change Intelligence."""

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --- Enums ---
class ChangeType(StrEnum):
    """Category of operational or infrastructure change."""

    GIT_COMMIT = "GIT_COMMIT"
    DEPLOYMENT = "DEPLOYMENT"
    CONFIGURATION = "CONFIGURATION"
    RELEASE = "RELEASE"
    UNKNOWN = "UNKNOWN"


class CausalChangeType(StrEnum):
    """Classification of causal or contributing change factor."""

    CONFIG_REGRESSION = "CONFIG_REGRESSION"
    CODE_REGRESSION = "CODE_REGRESSION"
    DEPLOYMENT_FAILURE = "DEPLOYMENT_FAILURE"
    DEPENDENCY_VERSION_CHANGE = "DEPENDENCY_VERSION_CHANGE"
    RESOURCE_LIMIT_CHANGE = "RESOURCE_LIMIT_CHANGE"
    UNRELATED_CHANGE = "UNRELATED_CHANGE"
    UNKNOWN = "UNKNOWN"


# --- Sensitive Keys & Redaction Patterns ---
_SENSITIVE_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"database[_-]?url", re.IGNORECASE),
    re.compile(r"db[_-]?pass", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"cert(ificate)?", re.IGNORECASE),
)

REDACTED_VALUE: str = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Determine whether a configuration key or parameter name matches secret patterns."""
    normalized = key.strip()
    return any(pattern.search(normalized) is not None for pattern in _SENSITIVE_KEY_PATTERNS)


# --- Configuration Change Model ---
class ConfigurationChange(BaseModel):
    """Single configuration parameter change diff with deterministic secret protection."""

    model_config = ConfigDict(from_attributes=True)

    key: str = Field(description="Configuration parameter name")
    old_value: Any | None = Field(default=None, description="Previous parameter value")
    new_value: Any | None = Field(default=None, description="New parameter value")
    scope: str = Field(default="service", description="Configuration scope (service, global, db)")
    sensitive: bool = Field(default=False, description="Whether this key is considered sensitive")

    def model_post_init(self, __context: Any) -> None:
        """Enforce deterministic redaction if the key name matches sensitive patterns."""
        if not self.sensitive and is_sensitive_key(self.key):
            self.sensitive = True
        if self.sensitive:
            if self.old_value is not None and self.old_value != REDACTED_VALUE:
                self.old_value = REDACTED_VALUE
            if self.new_value is not None and self.new_value != REDACTED_VALUE:
                self.new_value = REDACTED_VALUE


# --- Operational Change Model ---
class OperationalChange(BaseModel):
    """Structured representation of a deployment, commit, or configuration change."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Unique change identifier")
    source: str = Field(
        description="Origin of the change record (e.g. git, deployment_registry, demo_service)"
    )
    change_type: ChangeType = Field(description="Category of the change event")
    service: str = Field(description="Affected service name")
    timestamp: datetime = Field(
        description="Exact timestamp when the change occurred or was deployed"
    )
    actor: str | None = Field(default=None, description="Author or system triggering the change")
    version: str | None = Field(default=None, description="Target or deployed version identifier")
    commit_sha: str | None = Field(default=None, description="Associated Git commit SHA")
    deployment_id: str | None = Field(
        default=None, description="Associated deployment or release ID"
    )
    title: str = Field(description="Short summary of the change")
    description: str | None = Field(
        default=None, description="Detailed explanation or commit message"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary structured metadata"
    )
    files_changed: list[str] = Field(
        default_factory=list, description="List of file paths modified in this change"
    )
    config_changes: list[ConfigurationChange] = Field(
        default_factory=list, description="Structured list of configuration key-value diffs"
    )
    previous_version: str | None = Field(
        default=None, description="Previous version identifier before change"
    )
    new_version: str | None = Field(default=None, description="New version identifier after change")

    def model_post_init(self, __context: Any) -> None:
        """Enforce secret redaction on all nested config changes and sensitive metadata."""
        # Sanitize config changes
        sanitized_configs: list[ConfigurationChange] = []
        for cfg in self.config_changes:
            if not cfg.sensitive and is_sensitive_key(cfg.key):
                cfg = cfg.model_copy(
                    update={
                        "sensitive": True,
                        "old_value": REDACTED_VALUE if cfg.old_value is not None else None,
                        "new_value": REDACTED_VALUE if cfg.new_value is not None else None,
                    }
                )
            sanitized_configs.append(cfg)
        self.config_changes = sanitized_configs

        # Sanitize metadata keys
        for key in list(self.metadata.keys()):
            if is_sensitive_key(key):
                self.metadata[key] = REDACTED_VALUE


# --- Deployment Record Model ---
class DeploymentRecord(BaseModel):
    """Historical deployment record captured from CI/CD or runtime environments."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str = Field(description="Unique deployment identifier (e.g. deploy-002)")
    service: str = Field(description="Target service name")
    version: str = Field(default="latest", description="Deployed application version or tag")
    commit_sha: str | None = Field(default=None, description="Deployed commit SHA")
    environment: str = Field(default="production", description="Target environment")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Deployment trigger / start timestamp",
    )
    completed_at: datetime | None = Field(
        default=None, description="Deployment completion timestamp"
    )
    status: str = Field(
        default="COMPLETED", description="Deployment status (e.g. COMPLETED, FAILED)"
    )
    config_snapshot_id: str | None = Field(
        default=None, description="Snapshot identifier for active configuration"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    config_changes: list[ConfigurationChange] = Field(default_factory=list)

    @classmethod
    def model_validate(cls, obj: Any, *args: Any, **kwargs: Any) -> "DeploymentRecord":
        if isinstance(obj, dict) and "started_at" not in obj and "timestamp" in obj:
            obj_copy = dict(obj)
            obj_copy["started_at"] = obj_copy["timestamp"]
            return super().model_validate(obj_copy, *args, **kwargs)
        return super().model_validate(obj, *args, **kwargs)


# --- Correlation Assessment Model ---
class ChangeCorrelation(BaseModel):
    """Multi-factor correlation analysis linking a change to an incident's symptoms."""

    change_id: str = Field(description="Referenced OperationalChange identifier")
    temporal_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Temporal proximity score based on time delta from incident (0.0 to 1.0)",
    )
    component_match: bool = Field(
        description="Whether the changed component/service matches the incident service"
    )
    symptom_match: bool = Field(
        description="Whether the change description/diff semantically aligns with failure symptoms"
    )
    evidence_links: list[str] = Field(
        default_factory=list,
        description="Current telemetry EvidenceItem IDs supporting the change as causal",
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Current telemetry EvidenceItem IDs contradicting the change as causal",
    )
    relevance_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Aggregated causal relevance score combining temporal, component, and symptom alignment",
    )
    causal_category: CausalChangeType = Field(
        default=CausalChangeType.UNKNOWN,
        description="Classified failure category for the change",
    )
    is_causal_candidate: bool = Field(
        default=False,
        description="True only if multi-factor correlation exceeds verification threshold (never time alone)",
    )
    explanation: str = Field(
        default="", description="Human/LLM readable justification of the correlation score"
    )


# --- Redaction Utility ---
def sanitize_change_for_prompt(change: OperationalChange) -> str:
    """Format an OperationalChange into a concise, safe string for LLM prompt insertion."""
    diff_parts: list[str] = []
    for cfg in change.config_changes:
        old_val = REDACTED_VALUE if cfg.sensitive else cfg.old_value
        new_val = REDACTED_VALUE if cfg.sensitive else cfg.new_value
        diff_parts.append(f"  * {cfg.key}: {old_val} -> {new_val}")

    diff_str = "\n".join(diff_parts) if diff_parts else "  (no config diffs)"
    files_str = ", ".join(change.files_changed[:5]) if change.files_changed else "none"

    return (
        f"- ID: {change.id} | Type: {change.change_type.value} | Service: {change.service} | "
        f"Timestamp: {change.timestamp.isoformat()}\n"
        f"  Title: {change.title}\n"
        f"  Files: {files_str}\n"
        f"  Config Diff:\n{diff_str}"
    )
