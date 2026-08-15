"""TypedDict state definition for LangGraph incident investigation workflow."""

import operator
from typing import Annotated, Any, TypedDict

from faultwarden.schemas.evidence import (
    DeploymentEvent,
    EvidenceItem,
    LogEntry,
    MetricData,
    TraceSpan,
)
from faultwarden.schemas.hypothesis import Hypothesis, RootCauseAnalysis
from faultwarden.schemas.remediation import RemediationProposal


class IncidentInvestigationState(TypedDict, total=False):
    """Complete typed state passed across all LangGraph investigation nodes."""

    # --- Primary Identifiers & Context ---
    incident_id: str
    alert: dict[str, Any]
    incident: dict[str, Any] | None

    # --- Telemetry & Collected Evidence (appended across steps) ---
    evidence: Annotated[list[EvidenceItem], operator.add]
    metrics: Annotated[list[MetricData], operator.add]
    logs: Annotated[list[LogEntry], operator.add]
    traces: Annotated[list[TraceSpan], operator.add]
    recent_changes: Annotated[list[DeploymentEvent], operator.add]

    # --- Reasoning & Hypotheses ---
    hypotheses: Annotated[list[Hypothesis], operator.add]
    selected_hypothesis: Hypothesis | None
    root_cause: RootCauseAnalysis | None

    # --- Remediation ---
    remediation_proposals: Annotated[list[RemediationProposal], operator.add]

    # --- Workflow Metadata & Error Tracking ---
    iteration_count: int
    errors: Annotated[list[str], operator.add]
