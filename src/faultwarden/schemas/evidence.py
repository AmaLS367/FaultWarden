"""Evidence domain models gathered during incident investigation."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# --- Evidence Types ---
class EvidenceType(StrEnum):
    """Category of a collected piece of investigation evidence."""

    ALERT = "ALERT"
    METRIC = "METRIC"
    LOG = "LOG"
    TRACE = "TRACE"
    DEPLOYMENT = "DEPLOYMENT"
    SYSTEM_STATE = "SYSTEM_STATE"


# --- Specific Evidence Models ---
class MetricDataPoint(BaseModel):
    """Single timestamped metric sample."""

    timestamp: datetime
    value: float


class MetricData(BaseModel):
    """Query result for a specific Prometheus metric."""

    query: str
    labels: dict[str, str] = Field(default_factory=dict)
    values: list[MetricDataPoint] = Field(default_factory=list)
    summary: str = ""


class LogEntry(BaseModel):
    """Single log entry retrieved from Loki or log collector."""

    timestamp: datetime
    level: str = "INFO"
    message: str
    labels: dict[str, str] = Field(default_factory=dict)


class TraceSpan(BaseModel):
    """Distributed tracing span information."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    service_name: str
    operation_name: str
    duration_ms: float
    status_code: str = "OK"
    attributes: dict[str, Any] = Field(default_factory=dict)


class DeploymentEvent(BaseModel):
    """Recent deployment or configuration change record."""

    service_name: str
    version_tag: str
    deployed_at: datetime
    commit_sha: str | None = None
    author: str | None = None
    description: str | None = None


# --- Generic Evidence Container ---
class EvidenceItem(BaseModel):
    """Generic structured container for any investigation evidence item."""

    id: str
    evidence_type: EvidenceType
    source: str = Field(description="Telemetry origin (e.g. prometheus, loki, alertmanager)")
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Reliability score of source (0.0 to 1.0)"
    )
    relevance: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Relevance to investigated incident (0.0 to 1.0)"
    )
    summary: str = Field(description="Human/LLM readable concise summary of this evidence")
    data: dict[str, Any] = Field(
        default_factory=dict, description="Raw structured payload or metric values"
    )
    query_reference: str | None = Field(
        default=None, description="PromQL or LogQL query that produced this evidence"
    )
