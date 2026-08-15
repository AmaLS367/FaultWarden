"""Unit tests for LangGraph incident response state machine."""

import pytest

from faultwarden.graph.builder import build_incident_graph
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.hypothesis import HypothesisStatus
from faultwarden.schemas.remediation import RemediationSafetyLevel


@pytest.mark.asyncio
async def test_langgraph_compilation_and_execution() -> None:
    """Verify that the LangGraph workflow compiles and deterministically executes all steps."""
    graph = build_incident_graph()
    assert graph is not None

    initial_state: IncidentInvestigationState = {
        "incident_id": "inc-test-1234",
        "alert": {
            "groupKey": "test-group",
            "commonLabels": {
                "alertname": "High5xxRate",
                "service": "demo-service",
                "severity": "critical",
            },
        },
        "incident": None,
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [],
        "iteration_count": 0,
        "errors": [],
    }

    final_state = await graph.ainvoke(initial_state)

    # Assert workflow execution populated all pipeline stages
    assert final_state["incident_id"] == "inc-test-1234"
    assert final_state["iteration_count"] >= 1
    assert len(final_state["metrics"]) > 0
    assert len(final_state["logs"]) > 0
    assert len(final_state["evidence"]) > 0
    assert len(final_state["hypotheses"]) >= 2
    assert final_state["selected_hypothesis"] is not None
    assert final_state["selected_hypothesis"].status == HypothesisStatus.VERIFIED
    assert final_state["root_cause"] is not None
    assert final_state["root_cause"].culprit_service == "demo-service"
    assert len(final_state["remediation_proposals"]) >= 1

    proposal = final_state["remediation_proposals"][0]
    assert proposal.highest_safety_level == RemediationSafetyLevel.LEVEL_1_SAFE_AUTOMATIC
    assert len(proposal.actions) == 2
