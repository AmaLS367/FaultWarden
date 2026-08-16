"""Service layer for executing and persisting LangGraph incident investigations."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from faultwarden.core.config import get_settings
from faultwarden.core.exceptions import (
    FaultWardenError,
    RemediationActionNotFoundError,
    RemediationApprovalStaleError,
    RemediationNotAwaitingApprovalError,
)
from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.session import get_session_factory
from faultwarden.graph.builder import get_production_graph
from faultwarden.integrations.executors import (
    check_remediation_recovered,
    execute_remediation_action,
)
from faultwarden.integrations.llm.provider import LLMProvider, get_llm_provider
from faultwarden.integrations.loki.client import LogsProvider, LokiClient
from faultwarden.integrations.prometheus.client import MetricsProvider, PrometheusClient
from faultwarden.schemas.incident import (
    IncidentStatus,
    IncidentUpdate,
)
from faultwarden.schemas.remediation import (
    AllowedAction,
    ApprovalDecision,
    ApprovalRequiredAction,
    PolicyDecisionType,
    PolicyResult,
    RejectedAction,
    RemediationAction,
    RemediationProposal,
    RemediationResult,
    RemediationStatus,
)
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.remediation_audit_service import RemediationAuditService

if TYPE_CHECKING:
    from faultwarden.graph.state import IncidentInvestigationState

logger = get_logger("faultwarden.services.investigation")


def _is_graph_paused(final_state: dict[str, Any]) -> bool:
    """Determine whether the graph execution paused on an interrupt."""
    interrupts = final_state.get("__interrupt__")
    return bool(interrupts)


class InvestigationService:
    """Orchestrates LangGraph investigation execution and persists findings into domain models."""

    def __init__(
        self,
        incident_service: IncidentService,
        metrics_provider: MetricsProvider | None = None,
        logs_provider: LogsProvider | None = None,
        llm_provider: LLMProvider | None = None,
        remediation_executor: (
            Callable[[RemediationAction], Awaitable[RemediationResult]] | None
        ) = None,
        remediation_validator: (Callable[[RemediationAction], Awaitable[bool]] | None) = None,
    ) -> None:
        self.incident_service = incident_service
        self.metrics_provider = metrics_provider
        self.logs_provider = logs_provider
        self.llm_provider = llm_provider
        self.remediation_executor = remediation_executor
        self.remediation_validator = remediation_validator

    def _build_run_config(self, thread_id: str) -> RunnableConfig:
        """Construct RunnableConfig supplying all configurable dependencies and the thread_id."""
        settings = get_settings()
        metrics = self.metrics_provider or PrometheusClient(settings.prometheus)
        logs = self.logs_provider or LokiClient(settings.loki)
        llm = self.llm_provider or get_llm_provider()
        executor = self.remediation_executor or execute_remediation_action
        validator = self.remediation_validator or check_remediation_recovered

        return {
            "configurable": {
                "thread_id": thread_id,
                "metrics_provider": metrics,
                "logs_provider": logs,
                "llm_provider": llm,
                "remediation_executor": executor,
                "remediation_validator": validator,
            }
        }

    def _decide_terminal_status(
        self,
        final_state: dict[str, Any],
        *,
        proposals_list: list[RemediationProposal],
        root_cause_val: Any,
        incident_id_str: str,
    ) -> tuple[IncidentStatus, str | None]:
        """Decide the incident's terminal status/resolution text after a completed (non-paused) graph run.

        Only a validated recovery (remediation_validation_passed is True) resolves the incident.
        A remediation that executed but failed validation leaves the incident active
        (REMEDIATION_PROPOSED) rather than falsely marking it RESOLVED or terminally FAILED.
        """
        validation_passed = final_state.get("remediation_validation_passed")
        rem_result = final_state.get("remediation_result")

        if validation_passed is True:
            return (
                IncidentStatus.RESOLVED,
                f"Remediation executed and validated: {rem_result.summary if rem_result else 'recovery confirmed.'}",
            )
        if validation_passed is False:
            return (
                IncidentStatus.REMEDIATION_PROPOSED,
                "Remediation executed but post-remediation validation did not confirm recovery; "
                "incident remains active for further investigation or manual intervention.",
            )
        if proposals_list:
            return (IncidentStatus.REMEDIATION_PROPOSED, None)
        if root_cause_val:
            return (IncidentStatus.ROOT_CAUSE_IDENTIFIED, None)

        # propose_remediation_node always emits a fallback proposal before finalize_investigation
        # runs, so this branch should be unreachable in practice. Guard against it anyway: never
        # leave an incident stuck in INVESTIGATING forever if that invariant is ever broken.
        logger.warning(
            "investigation_completed_without_output",
            incident_id=incident_id_str,
            graph_investigation_status=final_state.get("investigation_status"),
        )
        return (IncidentStatus.FAILED, None)

    async def _count_prior_remediations(self, incident_id: UUID) -> tuple[int, int]:
        """Count this incident's prior remediation attempts and auto-executions for limit enforcement."""
        audit_service = RemediationAuditService(self.incident_service.session)
        actions = await audit_service.list_actions_for_incident(incident_id)
        attempt_count = len(actions)
        auto_execution_count = sum(1 for a in actions if a.decision == PolicyDecisionType.ALLOWED)
        return attempt_count, auto_execution_count

    async def _persist_remediation(
        self,
        state_values: dict[str, Any],
        audit_service: RemediationAuditService,
    ) -> None:
        """Persist primary proposal, policy decision, and execution result if available."""
        policy_result: PolicyResult | None = state_values.get("remediation_policy_result")
        if policy_result is None:
            return

        proposals: list[RemediationProposal] = state_values.get("remediation_proposals", [])
        proposal_id_str: str | None = None
        if isinstance(policy_result, (AllowedAction, ApprovalRequiredAction)):
            proposal_id_str = policy_result.action.proposal_id
        elif isinstance(policy_result, RejectedAction):
            proposal_id_str = policy_result.proposal_id

        if proposal_id_str:
            primary_proposal = next(
                (p for p in proposals if str(p.id) == str(proposal_id_str)),
                None,
            )
            if primary_proposal is not None:
                proposal_uuid = UUID(str(primary_proposal.id))
                existing_proposal = await audit_service.get_proposal(proposal_uuid)
                if existing_proposal is None:
                    await audit_service.create_proposal(primary_proposal)
                    await audit_service.create_action_decision(policy_result)

        rem_result = state_values.get("remediation_result")
        if rem_result is not None:
            if isinstance(rem_result, dict):
                rem_result = RemediationResult.model_validate(rem_result)
            await audit_service.record_execution_result(rem_result)

    # --- Synchronous / Direct Graph Run ---
    async def run_investigation(self, incident_id: UUID | str) -> IncidentModel:
        """Run the complete LangGraph investigation workflow for an incident and persist the result."""
        incident = await self.incident_service.get_incident(incident_id)
        incident_id_str = str(incident.id)

        logger.info("investigation_run_triggered", incident_id=incident_id_str)

        thread_id = str(uuid4())

        # Deterministic limits are computed from prior-attempt history, never from the LLM.
        prior_attempt_count, prior_auto_execution_count = await self._count_prior_remediations(
            incident.id
        )

        initial_state: IncidentInvestigationState = {
            "incident_id": incident_id_str,
            "incident_context": {
                "title": incident.title,
                "severity": incident.severity.value
                if hasattr(incident.severity, "value")
                else str(incident.severity),
                "service": incident.service or "unknown",
            },
            "alert": incident.alert_payload or {},
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
            "investigation_status": "INVESTIGATING",
            "missing_evidence_queries": [],
            "summary": "",
            "errors": [],
            "remediation_prior_attempt_count": prior_attempt_count,
            "remediation_prior_auto_execution_count": prior_auto_execution_count,
        }

        graph = get_production_graph()
        run_config = self._build_run_config(thread_id)

        try:
            # Commit the INVESTIGATING transition and thread_id immediately so concurrent readers see it
            # right away, instead of holding one long-lived transaction open for the whole
            # (potentially 30-90s) graph run below.
            await self.incident_service.update_incident(
                incident.id,
                IncidentUpdate(
                    status=IncidentStatus.INVESTIGATING,
                    langgraph_thread_id=thread_id,
                ),
            )
            await self.incident_service.session.commit()

            final_state: dict[str, Any] = await graph.ainvoke(initial_state, config=run_config)
            audit_service = RemediationAuditService(self.incident_service.session)

            evidence_items = final_state.get("evidence", [])
            hypotheses_list = final_state.get("hypotheses", [])
            root_cause_val = final_state.get("root_cause")
            proposals_list = final_state.get("remediation_proposals", [])
            summary_val = final_state.get("summary", "")
            classification_val = final_state.get("classification")
            iteration_val = final_state.get("iteration_count", 1)

            # Check if graph paused on interrupt (e.g. Level-2 approval required)
            if _is_graph_paused(final_state):
                await self._persist_remediation(final_state, audit_service)

                update_data = IncidentUpdate(
                    status=IncidentStatus.AWAITING_APPROVAL,
                    evidence=evidence_items,
                    hypotheses=hypotheses_list,
                    root_cause=root_cause_val,
                    proposed_remediations=proposals_list,
                    summary=summary_val or incident.summary,
                    classification=classification_val,
                    iteration_count=iteration_val,
                )

                updated_incident = await self.incident_service.update_incident(
                    incident.id, update_data
                )
                await self.incident_service.session.commit()

                logger.info(
                    "remediation_awaiting_approval",
                    incident_id=incident_id_str,
                    thread_id=thread_id,
                    evidence_count=len(evidence_items),
                    hypotheses_count=len(hypotheses_list),
                    proposals_count=len(proposals_list),
                )

                return updated_incident

            # Completed normally
            await self._persist_remediation(final_state, audit_service)

            next_status, resolution_text = self._decide_terminal_status(
                final_state,
                proposals_list=proposals_list,
                root_cause_val=root_cause_val,
                incident_id_str=incident_id_str,
            )

            update_data = IncidentUpdate(
                status=next_status,
                evidence=evidence_items,
                hypotheses=hypotheses_list,
                root_cause=root_cause_val,
                proposed_remediations=proposals_list,
                summary=summary_val or incident.summary,
                classification=classification_val,
                iteration_count=iteration_val,
                resolution=resolution_text,
            )

            updated_incident = await self.incident_service.update_incident(incident.id, update_data)
            await self.incident_service.session.commit()

            logger.info(
                "investigation_run_completed",
                incident_id=incident_id_str,
                status=next_status.value,
                evidence_count=len(evidence_items),
                hypotheses_count=len(hypotheses_list),
                has_root_cause=root_cause_val is not None,
            )

            return updated_incident

        except Exception as exc:
            logger.error(
                "investigation_run_failed",
                incident_id=incident_id_str,
                error=str(exc),
            )
            try:
                await self.incident_service.session.rollback()
            except Exception as rollback_exc:
                logger.error(
                    "investigation_session_rollback_failed",
                    incident_id=incident_id_str,
                    error=str(rollback_exc),
                )
            # Write the failure record through a fresh session so it survives regardless of
            # how the caller's own session/transaction resolves.
            try:
                fail_summary = f"Investigation failed with error: {exc}"
                session_factory = get_session_factory()
                async with session_factory() as fail_session, fail_session.begin():
                    fail_service = IncidentService(fail_session)
                    await fail_service.update_incident(
                        incident.id,
                        IncidentUpdate(
                            status=IncidentStatus.FAILED,
                            summary=fail_summary,
                        ),
                    )
            except Exception as write_exc:
                logger.error(
                    "investigation_failure_record_write_failed",
                    incident_id=incident_id_str,
                    error=str(write_exc),
                )
            raise FaultWardenError(f"Investigation execution failed: {exc}") from exc

    # --- Resume Remediation Approval ---
    async def resume_remediation_approval(
        self,
        incident_id: UUID | str,
        *,
        decision: ApprovalDecision,
        approved_by: str,
    ) -> IncidentModel:
        """Resume a paused Level-2 remediation approval and run the graph to completion or the next pause."""
        incident = await self.incident_service.get_incident(incident_id)
        incident_id_str = str(incident.id)

        if incident.status != IncidentStatus.AWAITING_APPROVAL:
            raise RemediationNotAwaitingApprovalError(
                incident_id_str,
                current_status=incident.status.value
                if hasattr(incident.status, "value")
                else str(incident.status),
            )

        if not incident.langgraph_thread_id:
            raise RemediationNotAwaitingApprovalError(
                incident_id_str,
                current_status=f"Missing thread ID (status: {incident.status})",
            )

        audit_service = RemediationAuditService(self.incident_service.session)
        actions = await audit_service.list_actions_for_incident(incident.id)
        awaiting_actions = [a for a in actions if a.status == RemediationStatus.AWAITING_APPROVAL]

        if not awaiting_actions:
            raise RemediationActionNotFoundError(
                f"No action in AWAITING_APPROVAL status found for incident '{incident_id_str}'."
            )
        if len(awaiting_actions) > 1:
            raise FaultWardenError(
                f"Multiple ({len(awaiting_actions)}) actions in AWAITING_APPROVAL status found for incident '{incident_id_str}'."
            )

        action = awaiting_actions[0]

        # SQLite (dev/test) returns naive datetimes even for DateTime(timezone=True) columns;
        # Postgres (production) returns timezone-aware ones. Normalize before subtracting.
        created_at = action.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        timeout_seconds = get_settings().remediation.approval_timeout_seconds
        pending_seconds = (datetime.now(UTC) - created_at).total_seconds()
        if pending_seconds > timeout_seconds:
            raise RemediationApprovalStaleError(str(action.id), pending_seconds, timeout_seconds)

        approved = decision == ApprovalDecision.APPROVE
        await audit_service.record_approval_decision(
            action.id,
            approved=approved,
            approved_by=approved_by,
        )

        graph = get_production_graph()
        run_config = self._build_run_config(incident.langgraph_thread_id)

        try:
            resume_val = {
                "decision": decision.value if hasattr(decision, "value") else str(decision)
            }
            final_state: dict[str, Any] = await graph.ainvoke(
                Command(resume=resume_val),
                config=run_config,
            )

            evidence_items = final_state.get("evidence", [])
            hypotheses_list = final_state.get("hypotheses", [])
            root_cause_val = final_state.get("root_cause")
            proposals_list = final_state.get("remediation_proposals", [])
            summary_val = final_state.get("summary", "")
            classification_val = final_state.get("classification")
            iteration_val = final_state.get("iteration_count", 1)

            if _is_graph_paused(final_state):
                await self._persist_remediation(final_state, audit_service)

                update_data = IncidentUpdate(
                    status=IncidentStatus.AWAITING_APPROVAL,
                    evidence=evidence_items,
                    hypotheses=hypotheses_list,
                    root_cause=root_cause_val,
                    proposed_remediations=proposals_list,
                    summary=summary_val or incident.summary,
                    classification=classification_val,
                    iteration_count=iteration_val,
                )

                updated_incident = await self.incident_service.update_incident(
                    incident.id, update_data
                )
                await self.incident_service.session.commit()

                logger.info(
                    "remediation_awaiting_approval",
                    incident_id=incident_id_str,
                    thread_id=incident.langgraph_thread_id,
                )
                return updated_incident

            # Completed normally
            await self._persist_remediation(final_state, audit_service)

            next_status, resolution_text = self._decide_terminal_status(
                final_state,
                proposals_list=proposals_list,
                root_cause_val=root_cause_val,
                incident_id_str=incident_id_str,
            )

            update_data = IncidentUpdate(
                status=next_status,
                evidence=evidence_items,
                hypotheses=hypotheses_list,
                root_cause=root_cause_val,
                proposed_remediations=proposals_list,
                summary=summary_val or incident.summary,
                classification=classification_val,
                iteration_count=iteration_val,
                resolution=resolution_text,
            )

            updated_incident = await self.incident_service.update_incident(incident.id, update_data)
            await self.incident_service.session.commit()

            logger.info(
                "remediation_approval_resumed_completed",
                incident_id=incident_id_str,
                decision=decision.value if hasattr(decision, "value") else str(decision),
                status=next_status.value,
            )

            return updated_incident

        except Exception as exc:
            logger.error(
                "investigation_resume_failed",
                incident_id=incident_id_str,
                error=str(exc),
            )
            try:
                await self.incident_service.session.rollback()
            except Exception as rollback_exc:
                logger.error(
                    "investigation_resume_rollback_failed",
                    incident_id=incident_id_str,
                    error=str(rollback_exc),
                )
            raise FaultWardenError(f"Investigation resume failed: {exc}") from exc


# --- Background Investigation Worker ---
async def run_background_investigation(incident_id: UUID | str) -> None:
    """Run an investigation inside an isolated DB session, intended for FastAPI BackgroundTasks."""
    logger.info("launching_background_investigation", incident_id=str(incident_id))
    session_factory = get_session_factory()
    try:
        async with session_factory() as session:
            incident_service = IncidentService(session)
            investigation_service = InvestigationService(incident_service)
            await investigation_service.run_investigation(incident_id)
    except Exception as exc:
        logger.error(
            "background_investigation_error",
            incident_id=str(incident_id),
            error=str(exc),
        )
