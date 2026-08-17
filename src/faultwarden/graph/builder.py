"""LangGraph StateGraph builder and compilation for incident investigation."""

from typing import Any, Literal

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from faultwarden.core.config import get_settings
from faultwarden.graph.checkpointer import get_checkpointer
from faultwarden.graph.nodes.classify import classify_incident_node
from faultwarden.graph.nodes.collect_additional import collect_additional_telemetry_node
from faultwarden.graph.nodes.collect_changes import collect_recent_changes_node
from faultwarden.graph.nodes.collect_logs import collect_initial_logs_node
from faultwarden.graph.nodes.collect_metrics import collect_initial_metrics_node
from faultwarden.graph.nodes.correlate import correlate_evidence_node
from faultwarden.graph.nodes.finalize import finalize_investigation_node
from faultwarden.graph.nodes.hypothesize import generate_hypotheses_node
from faultwarden.graph.nodes.propose_remediation import propose_remediation_node
from faultwarden.graph.nodes.remediation_approval import await_remediation_approval_node
from faultwarden.graph.nodes.remediation_execution import (
    execute_remediation_node,
    validate_remediation_node,
)
from faultwarden.graph.nodes.remediation_policy import evaluate_remediation_policy_node
from faultwarden.graph.nodes.retrieve_memory import retrieve_incident_memory_node
from faultwarden.graph.nodes.verify import verify_hypothesis_node
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.remediation import (
    AllowedAction,
    ApprovalDecision,
    ApprovalRequiredAction,
)

# Cached production graph compiled with the durable checkpointer
_production_graph: CompiledStateGraph[IncidentInvestigationState, Any, Any, Any] | None = None


# --- Conditional Routing Logic ---
def should_continue_investigation(
    state: IncidentInvestigationState,
) -> Literal["collect_additional_telemetry", "propose_remediation"]:
    """Determine whether to loop for missing evidence or advance to remediation proposals."""
    # If a root cause is verified, proceed directly to remediation proposals
    if state.get("root_cause") is not None:
        return "propose_remediation"

    # If maximum bounded iterations reached, stop looping and propose best-effort remediation
    settings = get_settings()
    max_iterations = settings.investigation.max_iterations
    current_iteration = state.get("iteration_count", 1)
    if current_iteration >= max_iterations:
        return "propose_remediation"

    # If no missing queries were identified, cannot collect more telemetry; advance
    missing_queries = state.get("missing_evidence_queries", [])
    if not missing_queries:
        return "propose_remediation"

    return "collect_additional_telemetry"


def route_remediation_policy_result(
    state: IncidentInvestigationState,
) -> Literal["execute_remediation", "await_remediation_approval", "finalize_investigation"]:
    """Route based on the deterministic policy evaluation and eligibility gate outcome."""
    eligibility = state.get("remediation_eligibility")
    if eligibility is not None and not eligibility.eligible:
        return "finalize_investigation"

    policy_res = state.get("remediation_policy_result")
    if isinstance(policy_res, AllowedAction):
        return "execute_remediation"
    if isinstance(policy_res, ApprovalRequiredAction):
        return "await_remediation_approval"
    return "finalize_investigation"


def route_approval_decision(
    state: IncidentInvestigationState,
) -> Literal["execute_remediation", "finalize_investigation"]:
    """Route based on human operator approval decision after interrupt resume."""
    decision = state.get("remediation_approval_decision")
    if decision == ApprovalDecision.APPROVE.value:
        return "execute_remediation"
    return "finalize_investigation"


# --- Graph Construction ---
def build_incident_graph(
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> CompiledStateGraph[IncidentInvestigationState, Any, Any, Any]:
    """Construct and compile the cyclical LangGraph incident investigation workflow."""
    workflow = StateGraph(IncidentInvestigationState)

    # Register workflow nodes
    workflow.add_node("classify_incident", classify_incident_node)
    workflow.add_node("collect_initial_metrics", collect_initial_metrics_node)
    workflow.add_node("collect_initial_logs", collect_initial_logs_node)
    workflow.add_node("retrieve_incident_memory", retrieve_incident_memory_node)
    workflow.add_node("collect_recent_changes", collect_recent_changes_node)
    workflow.add_node("correlate_evidence", correlate_evidence_node)
    workflow.add_node("generate_hypotheses", generate_hypotheses_node)
    workflow.add_node("verify_hypothesis", verify_hypothesis_node)
    workflow.add_node("collect_additional_telemetry", collect_additional_telemetry_node)
    workflow.add_node("propose_remediation", propose_remediation_node)
    workflow.add_node("evaluate_remediation_policy", evaluate_remediation_policy_node)
    workflow.add_node("await_remediation_approval", await_remediation_approval_node)
    workflow.add_node("execute_remediation", execute_remediation_node)
    workflow.add_node("validate_remediation", validate_remediation_node)
    workflow.add_node("finalize_investigation", finalize_investigation_node)

    # Establish linear telemetry gathering pipeline
    workflow.add_edge(START, "classify_incident")
    workflow.add_edge("classify_incident", "collect_initial_metrics")
    workflow.add_edge("collect_initial_metrics", "collect_initial_logs")
    workflow.add_edge("collect_initial_logs", "retrieve_incident_memory")
    workflow.add_edge("retrieve_incident_memory", "collect_recent_changes")
    workflow.add_edge("collect_recent_changes", "correlate_evidence")
    workflow.add_edge("correlate_evidence", "generate_hypotheses")
    workflow.add_edge("generate_hypotheses", "verify_hypothesis")

    # Conditional branching after verification
    workflow.add_conditional_edges(
        "verify_hypothesis",
        should_continue_investigation,
        {
            "collect_additional_telemetry": "collect_additional_telemetry",
            "propose_remediation": "propose_remediation",
        },
    )

    # Loop back from additional telemetry collection to hypothesis re-evaluation
    workflow.add_edge("collect_additional_telemetry", "generate_hypotheses")

    # Remediation policy evaluation branch
    workflow.add_edge("propose_remediation", "evaluate_remediation_policy")
    workflow.add_conditional_edges(
        "evaluate_remediation_policy",
        route_remediation_policy_result,
        {
            "execute_remediation": "execute_remediation",
            "await_remediation_approval": "await_remediation_approval",
            "finalize_investigation": "finalize_investigation",
        },
    )

    # Human-in-the-loop approval branch
    workflow.add_conditional_edges(
        "await_remediation_approval",
        route_approval_decision,
        {
            "execute_remediation": "execute_remediation",
            "finalize_investigation": "finalize_investigation",
        },
    )

    # Execution, validation stub, and finalization
    workflow.add_edge("execute_remediation", "validate_remediation")
    workflow.add_edge("validate_remediation", "finalize_investigation")
    workflow.add_edge("finalize_investigation", END)

    return workflow.compile(checkpointer=checkpointer)


# --- Production Graph Accessor ---
def get_production_graph() -> CompiledStateGraph[IncidentInvestigationState, Any, Any, Any]:
    """Return the cached production StateGraph compiled with the active checkpointer."""
    global _production_graph
    if _production_graph is None:
        checkpointer = get_checkpointer()
        _production_graph = build_incident_graph(checkpointer=checkpointer)
    return _production_graph


def reset_production_graph() -> None:
    """Reset the cached production graph singleton (useful during test resets)."""
    global _production_graph
    _production_graph = None
