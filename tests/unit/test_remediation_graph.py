"""Unit tests for remediation graph evaluation, interrupt/pause, resume, and execution."""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from faultwarden.core.config import get_settings
from faultwarden.graph.builder import build_incident_graph
from faultwarden.graph.state import IncidentInvestigationState
from faultwarden.schemas.classification import IncidentClassification
from faultwarden.schemas.hypothesis import (
    HypothesisCandidate,
    HypothesisGenerationResponse,
    HypothesisVerificationResponse,
)
from faultwarden.schemas.incident import IncidentSeverity
from faultwarden.schemas.remediation import (
    ActionType,
    ApprovalDecision,
    PolicyDecisionType,
    RemediationAction,
    RemediationActionCandidate,
    RemediationExecutionStatus,
    RemediationProposalResponse,
    RemediationResult,
)


def _make_initial_state(incident_id: str = "inc-test-rem-graph") -> IncidentInvestigationState:
    """Helper to create a standard initial investigation state."""
    return {
        "incident_id": incident_id,
        "incident_context": {
            "title": "High Latency in demo-service",
            "severity": "CRITICAL",
            "service": "demo-service",
        },
        "alert": {
            "groupKey": "test-group",
            "commonLabels": {
                "alertname": "DemoServiceHighLatency",
                "service": "demo-service",
                "severity": "critical",
            },
            "commonAnnotations": {
                "summary": "High latency in demo-service",
                "description": "Requests taking > 2s",
            },
        },
        "classification": None,
        "evidence": [],
        "metrics": [],
        "logs": [],
        "traces": [],
        "recent_changes": [],
        "hypotheses": [],
        "selected_hypothesis": None,
        "root_cause": None,
        "remediation_proposals": [],
        "iteration_count": 1,
        "missing_evidence_queries": [],
        "investigation_status": "INVESTIGATING",
        "summary": "",
        "errors": [],
    }


def _create_mock_llm(action_candidates: list[RemediationActionCandidate]) -> AsyncMock:
    """Create a mock LLM that produces verified root-cause and the specified remediation proposals."""
    mock_llm = AsyncMock()

    async def _mock_generate_structured(
        prompt: str,
        schema: type[Any],
        system_prompt: str | None = None,
    ) -> Any:
        schema_name = getattr(schema, "__name__", str(schema))
        if schema_name == "IncidentClassification":
            return IncidentClassification(
                incident_type="service_degradation",
                severity_assessment=IncidentSeverity.CRITICAL,
                primary_service="demo-service",
                affected_components=["demo-service"],
                suggested_queries=[],
                reasoning="Classification reasoning",
            )
        if schema_name == "HypothesisGenerationResponse":
            return HypothesisGenerationResponse(
                hypotheses=[
                    HypothesisCandidate(
                        title="Database Connection Pool Saturation",
                        description="Connection pool exhausted under load",
                        affected_component="demo-service",
                        confidence_score=0.88,
                        supporting_evidence_ids=[],
                        refuting_evidence_ids=[],
                        missing_evidence_needed=[],
                        reasoning_summary="Observed connection timeouts",
                    )
                ]
            )
        if schema_name == "HypothesisVerificationResponse":
            return HypothesisVerificationResponse(
                is_verified=True,
                confidence_score=0.92,
                reasoning="Telemetry confirms DB saturation",
                additional_queries_needed=[],
            )
        if schema_name == "RemediationProposalResponse":
            return RemediationProposalResponse(
                title="Remediation Plan",
                summary="Execute selected remediation",
                actions=action_candidates,
            )
        return schema()

    mock_llm.generate_structured.side_effect = _mock_generate_structured
    mock_llm.generate_text.return_value = "Investigation completed successfully."
    return mock_llm


def _create_mock_executor() -> AsyncMock:
    """Create a mock remediation executor that returns a successful execution result."""
    mock_exec = AsyncMock()

    async def _fake_executor(action: RemediationAction) -> RemediationResult:
        return RemediationResult(
            action_id=action.id,
            status=RemediationExecutionStatus.SUCCEEDED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            success=True,
            summary=f"Successfully executed {action.action_type}",
        )

    mock_exec.side_effect = _fake_executor
    return mock_exec


@pytest.mark.asyncio
async def test_level_2_interrupt_and_approve_resume_executes_action() -> None:
    """Test 1: Level-2 action pauses on interrupt, resume with APPROVE completes and executes once."""
    checkpointer = InMemorySaver()
    graph = build_incident_graph(checkpointer=checkpointer)

    # Level-2 candidate action (RESTART_REGISTERED_SERVICE)
    level_2_candidate = RemediationActionCandidate(
        name="Restart Registered Demo Service",
        target_service="demo-service",
        safety_level=2,
        action_type=ActionType.RESTART_REGISTERED_SERVICE,
        parameters={"service_id": "demo-service"},
        description="Restart the demo service container",
    )
    mock_llm = _create_mock_llm([level_2_candidate])
    mock_executor = _create_mock_executor()

    run_config = {
        "configurable": {
            "thread_id": "test-thread-l2-approve",
            "llm_provider": mock_llm,
            "remediation_executor": mock_executor,
        }
    }

    initial_state = _make_initial_state("inc-l2-approve")
    paused_state = await graph.ainvoke(initial_state, config=run_config)

    # Assert graph paused on interrupt
    assert "__interrupt__" in paused_state
    assert len(paused_state["__interrupt__"]) > 0
    assert (
        paused_state["remediation_policy_result"].decision == PolicyDecisionType.APPROVAL_REQUIRED
    )
    mock_executor.assert_not_called()

    # Resume with APPROVE decision
    resume_state = await graph.ainvoke(
        Command(resume={"decision": ApprovalDecision.APPROVE.value}),
        config=run_config,
    )

    # Assert completed normally after resume
    assert "__interrupt__" not in resume_state
    assert resume_state["remediation_approval_decision"] == ApprovalDecision.APPROVE.value
    assert resume_state.get("remediation_result") is not None
    assert resume_state["remediation_result"].success is True
    assert resume_state["remediation_validation_passed"] is True
    mock_executor.assert_awaited_once()


@pytest.mark.asyncio
async def test_level_2_interrupt_and_reject_resume_skips_execution() -> None:
    """Test 2: Level-2 action pauses on interrupt, resume with REJECT completes without executing."""
    checkpointer = InMemorySaver()
    graph = build_incident_graph(checkpointer=checkpointer)

    level_2_candidate = RemediationActionCandidate(
        name="Restart Registered Demo Service",
        target_service="demo-service",
        safety_level=2,
        action_type=ActionType.RESTART_REGISTERED_SERVICE,
        parameters={"service_id": "demo-service"},
        description="Restart the demo service container",
    )
    mock_llm = _create_mock_llm([level_2_candidate])
    mock_executor = _create_mock_executor()

    run_config = {
        "configurable": {
            "thread_id": "test-thread-l2-reject",
            "llm_provider": mock_llm,
            "remediation_executor": mock_executor,
        }
    }

    initial_state = _make_initial_state("inc-l2-reject")
    paused_state = await graph.ainvoke(initial_state, config=run_config)

    assert "__interrupt__" in paused_state
    mock_executor.assert_not_called()

    # Resume with REJECT decision
    resume_state = await graph.ainvoke(
        Command(resume={"decision": ApprovalDecision.REJECT.value}),
        config=run_config,
    )

    assert "__interrupt__" not in resume_state
    assert resume_state["remediation_approval_decision"] == ApprovalDecision.REJECT.value
    assert resume_state.get("remediation_result") is None
    mock_executor.assert_not_called()


@pytest.mark.asyncio
async def test_level_1_auto_execute_path_runs_without_pause() -> None:
    """Test 3: Level-1 proposal auto-executes immediately without reaching approval pause."""
    checkpointer = InMemorySaver()
    graph = build_incident_graph(checkpointer=checkpointer)

    level_1_candidate = RemediationActionCandidate(
        name="Reset Demo Service Fault Injection",
        target_service="demo-service",
        safety_level=1,
        action_type=ActionType.RESET_DEMO_FAILURE,
        parameters={"service": "demo-service"},
        description="Reset error mode on demo service",
    )
    mock_llm = _create_mock_llm([level_1_candidate])
    mock_executor = _create_mock_executor()

    run_config = {
        "configurable": {
            "thread_id": "test-thread-l1-auto",
            "llm_provider": mock_llm,
            "remediation_executor": mock_executor,
        }
    }

    initial_state = _make_initial_state("inc-l1-auto")
    result_state = await graph.ainvoke(initial_state, config=run_config)

    # Assert no interrupt occurred
    assert "__interrupt__" not in result_state
    assert result_state["remediation_policy_result"].decision == PolicyDecisionType.ALLOWED
    assert result_state.get("remediation_approval_decision") is None
    assert result_state.get("remediation_result") is not None
    assert result_state["remediation_result"].success is True
    mock_executor.assert_awaited_once()


@pytest.mark.asyncio
async def test_policy_rejected_proposal_routes_to_finalize_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 4: Proposal rejected by policy (e.g. disabled remediation) routes straight to finalize."""
    # Override settings to disable remediation pipeline
    current_settings = get_settings()
    mock_settings = current_settings.model_copy(update={"remediation_enabled": False})
    monkeypatch.setattr(
        "faultwarden.graph.nodes.remediation_policy.get_settings",
        lambda: mock_settings,
    )

    checkpointer = InMemorySaver()
    graph = build_incident_graph(checkpointer=checkpointer)

    candidate = RemediationActionCandidate(
        name="Reset Demo Service",
        target_service="demo-service",
        safety_level=1,
        action_type=ActionType.RESET_DEMO_FAILURE,
        parameters={"service": "demo-service"},
        description="Reset error mode",
    )
    mock_llm = _create_mock_llm([candidate])
    mock_executor = _create_mock_executor()

    run_config = {
        "configurable": {
            "thread_id": "test-thread-rejected",
            "llm_provider": mock_llm,
            "remediation_executor": mock_executor,
        }
    }

    initial_state = _make_initial_state("inc-rejected")
    result_state = await graph.ainvoke(initial_state, config=run_config)

    assert "__interrupt__" not in result_state
    assert result_state["remediation_policy_result"].decision == PolicyDecisionType.REJECTED
    assert result_state.get("remediation_approval_decision") is None
    assert result_state.get("remediation_result") is None
    mock_executor.assert_not_called()


@pytest.mark.asyncio
async def test_build_incident_graph_without_arguments_compiles_and_runs() -> None:
    """Test 5: build_incident_graph() with no arguments compiles and runs with default checkpointer=None."""
    graph = build_incident_graph()
    assert graph is not None

    initial_state = _make_initial_state("inc-no-args")
    result_state = await graph.ainvoke(initial_state)

    assert result_state["incident_id"] == "inc-no-args"
    assert result_state["iteration_count"] >= 1
    assert result_state["classification"] is not None
    assert (
        "__interrupt__" in result_state or result_state.get("investigation_status") == "COMPLETED"
    )
