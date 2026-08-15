"""LangGraph StateGraph builder and compilation for incident investigation."""

from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from faultwarden.graph.nodes.classify import classify_incident_node
from faultwarden.graph.nodes.collect_context import collect_context_node
from faultwarden.graph.nodes.hypothesize import generate_hypotheses_node
from faultwarden.graph.nodes.propose_remediation import propose_remediation_node
from faultwarden.graph.nodes.verify import verify_hypothesis_node
from faultwarden.graph.state import IncidentInvestigationState


def build_incident_graph() -> CompiledStateGraph[IncidentInvestigationState, Any, Any, Any]:
    """Construct and compile the incident response LangGraph workflow."""
    workflow = StateGraph(IncidentInvestigationState)

    # Register workflow nodes
    workflow.add_node("classify_incident", classify_incident_node)
    workflow.add_node("collect_context", collect_context_node)
    workflow.add_node("generate_hypotheses", generate_hypotheses_node)
    workflow.add_node("verify_hypothesis", verify_hypothesis_node)
    workflow.add_node("propose_remediation", propose_remediation_node)

    # Establish linear deterministic pipeline
    workflow.add_edge(START, "classify_incident")
    workflow.add_edge("classify_incident", "collect_context")
    workflow.add_edge("collect_context", "generate_hypotheses")
    workflow.add_edge("generate_hypotheses", "verify_hypothesis")
    workflow.add_edge("verify_hypothesis", "propose_remediation")
    workflow.add_edge("propose_remediation", END)

    return workflow.compile()
