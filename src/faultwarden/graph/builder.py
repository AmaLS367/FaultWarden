"""LangGraph StateGraph builder and compilation for incident investigation."""

from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from faultwarden.core.config import get_settings
from faultwarden.graph.nodes.classify import classify_incident_node
from faultwarden.graph.nodes.collect_additional import collect_additional_telemetry_node
from faultwarden.graph.nodes.collect_logs import collect_initial_logs_node
from faultwarden.graph.nodes.collect_metrics import collect_initial_metrics_node
from faultwarden.graph.nodes.correlate import correlate_evidence_node
from faultwarden.graph.nodes.finalize import finalize_investigation_node
from faultwarden.graph.nodes.hypothesize import generate_hypotheses_node
from faultwarden.graph.nodes.propose_remediation import propose_remediation_node
from faultwarden.graph.nodes.verify import verify_hypothesis_node
from faultwarden.graph.state import IncidentInvestigationState


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


# --- Graph Construction ---
def build_incident_graph() -> CompiledStateGraph[IncidentInvestigationState, Any, Any, Any]:
    """Construct and compile the cyclical LangGraph incident investigation workflow."""
    workflow = StateGraph(IncidentInvestigationState)

    # Register workflow nodes
    workflow.add_node("classify_incident", classify_incident_node)
    workflow.add_node("collect_initial_metrics", collect_initial_metrics_node)
    workflow.add_node("collect_initial_logs", collect_initial_logs_node)
    workflow.add_node("correlate_evidence", correlate_evidence_node)
    workflow.add_node("generate_hypotheses", generate_hypotheses_node)
    workflow.add_node("verify_hypothesis", verify_hypothesis_node)
    workflow.add_node("collect_additional_telemetry", collect_additional_telemetry_node)
    workflow.add_node("propose_remediation", propose_remediation_node)
    workflow.add_node("finalize_investigation", finalize_investigation_node)

    # Establish linear telemetry gathering pipeline
    workflow.add_edge(START, "classify_incident")
    workflow.add_edge("classify_incident", "collect_initial_metrics")
    workflow.add_edge("collect_initial_metrics", "collect_initial_logs")
    workflow.add_edge("collect_initial_logs", "correlate_evidence")
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

    # Wrap up through remediation and finalization
    workflow.add_edge("propose_remediation", "finalize_investigation")
    workflow.add_edge("finalize_investigation", END)

    return workflow.compile()
