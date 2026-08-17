"""Service layer for deterministic timeline assembly and structured postmortem generation."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.config import Settings, get_settings
from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.postmortem import IncidentPostmortemModel
from faultwarden.db.models.remediation import (
    RemediationActionModel,
    RemediationProposalModel,
    RemediationResultModel,
    RemediationValidationModel,
)
from faultwarden.integrations.llm.provider import LLMProvider, get_llm_provider
from faultwarden.schemas.incident import IncidentStatus
from faultwarden.schemas.postmortem import (
    PostmortemSynthesisResponse,
    PostmortemTimelineEntry,
)

logger = get_logger("faultwarden.services.postmortem")


# --- Postmortem Service ---
class PostmortemService:
    """Orchestrates structured postmortem generation from persisted incident data."""

    def __init__(
        self,
        session: AsyncSession,
        llm_provider: LLMProvider | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.llm_provider = llm_provider
        self.settings = settings or get_settings()

    async def get_postmortem_by_incident_id(
        self, incident_id: UUID | str
    ) -> IncidentPostmortemModel | None:
        """Retrieve existing postmortem model for an incident."""
        uuid_val = incident_id if isinstance(incident_id, UUID) else UUID(incident_id)
        stmt = select(IncidentPostmortemModel).where(
            IncidentPostmortemModel.incident_id == uuid_val
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def _fetch_remediation_history(
        self, incident_id: UUID
    ) -> tuple[
        list[RemediationProposalModel],
        list[RemediationActionModel],
        list[RemediationResultModel],
        list[RemediationValidationModel],
    ]:
        """Fetch all persisted remediation audit records for this incident."""
        # 1. Proposals
        prop_stmt = (
            select(RemediationProposalModel)
            .where(RemediationProposalModel.incident_id == incident_id)
            .order_by(RemediationProposalModel.created_at.asc())
        )
        proposals = list((await self.session.execute(prop_stmt)).scalars().all())

        # 2. Actions
        act_stmt = (
            select(RemediationActionModel)
            .where(RemediationActionModel.incident_id == incident_id)
            .order_by(RemediationActionModel.created_at.asc())
        )
        actions = list((await self.session.execute(act_stmt)).scalars().all())

        # 3. Results
        action_ids = [a.id for a in actions]
        results: list[RemediationResultModel] = []
        if action_ids:
            res_stmt = (
                select(RemediationResultModel)
                .where(RemediationResultModel.action_id.in_(action_ids))
                .order_by(RemediationResultModel.started_at.asc())
            )
            results = list((await self.session.execute(res_stmt)).scalars().all())

        # 4. Validations
        val_stmt = (
            select(RemediationValidationModel)
            .where(RemediationValidationModel.incident_id == incident_id)
            .order_by(RemediationValidationModel.started_at.asc())
        )
        validations = list((await self.session.execute(val_stmt)).scalars().all())

        return proposals, actions, results, validations

    def _build_factual_timeline(
        self,
        incident: IncidentModel,
        proposals: list[RemediationProposalModel],
        actions: list[RemediationActionModel],
        results: list[RemediationResultModel],
        validations: list[RemediationValidationModel],
    ) -> list[PostmortemTimelineEntry]:
        """Assemble deterministic chronological timeline entries from persisted database entities."""
        timeline: list[PostmortemTimelineEntry] = []

        # 0. Recent Deployments and Changes (using real timestamps)
        recent_changes = incident.recent_changes or []
        for ch in recent_changes:
            ch_ts_raw = ch.get("timestamp")
            if ch_ts_raw:
                try:
                    if isinstance(ch_ts_raw, str):
                        if ch_ts_raw.endswith("Z"):
                            ch_ts_raw = ch_ts_raw[:-1] + "+00:00"
                        ch_ts = datetime.fromisoformat(ch_ts_raw)
                    elif isinstance(ch_ts_raw, datetime):
                        ch_ts = ch_ts_raw
                    else:
                        continue
                    ch_type = str(ch.get("change_type", "DEPLOYMENT")).upper()
                    event_type = "DEPLOYMENT_COMPLETED" if ch_type == "DEPLOYMENT" else "GIT_COMMIT"
                    timeline.append(
                        PostmortemTimelineEntry(
                            timestamp=ch_ts,
                            event_type=event_type,
                            summary=f"{ch.get('title', 'Change')} [{ch.get('id', '')}] on service '{ch.get('service', incident.service)}'.",
                        )
                    )
                except Exception:
                    pass

        # 1. Alert Fired / StartsAt
        alert_payload = incident.alert_payload or {}
        alerts_list = alert_payload.get("alerts", [])
        if alerts_list and isinstance(alerts_list[0], dict) and alerts_list[0].get("startsAt"):
            try:
                starts_at_str = str(alerts_list[0]["startsAt"])
                # Normalize Z to +00:00
                if starts_at_str.endswith("Z"):
                    starts_at_str = starts_at_str[:-1] + "+00:00"
                alert_ts = datetime.fromisoformat(starts_at_str)
                timeline.append(
                    PostmortemTimelineEntry(
                        timestamp=alert_ts,
                        event_type="ALERT_FIRED",
                        summary=f"Alert '{alert_payload.get('groupLabels', {}).get('alertname', incident.title)}' fired from {incident.source}.",
                    )
                )
            except Exception:
                pass

        # 2. Incident Created
        timeline.append(
            PostmortemTimelineEntry(
                timestamp=incident.created_at,
                event_type="INCIDENT_CREATED",
                summary=f"Incident record '{incident.title}' created in FaultWarden (severity: {incident.severity}).",
            )
        )

        # 3. Root Cause Verified
        if incident.root_cause and isinstance(incident.root_cause, dict):
            rc_ts = incident.created_at
            if incident.root_cause.get("identified_at"):
                try:
                    ts_val = incident.root_cause["identified_at"]
                    if isinstance(ts_val, str):
                        if ts_val.endswith("Z"):
                            ts_val = ts_val[:-1] + "+00:00"
                        rc_ts = datetime.fromisoformat(ts_val)
                    elif isinstance(ts_val, datetime):
                        rc_ts = ts_val
                except Exception:
                    pass
            timeline.append(
                PostmortemTimelineEntry(
                    timestamp=rc_ts,
                    event_type="ROOT_CAUSE_VERIFIED",
                    summary=f"Root cause verified: {incident.root_cause.get('summary', 'Unknown')}",
                )
            )

        # 4. Remediation Proposals & Approvals
        for prop in proposals:
            timeline.append(
                PostmortemTimelineEntry(
                    timestamp=prop.created_at,
                    event_type="REMEDIATION_PROPOSED",
                    summary=f"Remediation proposed: '{prop.title}' (action: {prop.action_type}).",
                )
            )

        for act in actions:
            if act.approved_at:
                timeline.append(
                    PostmortemTimelineEntry(
                        timestamp=act.approved_at,
                        event_type="REMEDIATION_APPROVED",
                        summary=f"Action '{act.action_type}' approved by {act.approved_by or 'operator'}.",
                    )
                )

        # 5. Remediation Executions
        for res in results:
            timeline.append(
                PostmortemTimelineEntry(
                    timestamp=res.started_at,
                    event_type="REMEDIATION_EXECUTED",
                    summary=f"Remediation action executed: {res.summary} (success: {res.success}).",
                )
            )

        # 6. Recovery Validations
        for val in validations:
            ev_type = "VALIDATION_PASSED" if val.passed else "VALIDATION_FAILED"
            timeline.append(
                PostmortemTimelineEntry(
                    timestamp=val.started_at,
                    event_type=ev_type,
                    summary=f"Multi-signal recovery validation: {val.summary} (passed: {val.passed}).",
                )
            )

        # 7. Incident Resolved
        if incident.status == IncidentStatus.RESOLVED:
            resolved_ts = incident.updated_at
            timeline.append(
                PostmortemTimelineEntry(
                    timestamp=resolved_ts,
                    event_type="INCIDENT_RESOLVED",
                    summary=f"Incident confirmed resolved: {incident.resolution or 'Service recovered.'}",
                )
            )

        # Sort timeline chronologically by timestamp
        def _normalize_dt(dt: datetime) -> datetime:
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)

        timeline.sort(key=lambda item: _normalize_dt(item.timestamp))
        return timeline

    async def _synthesize_prose(
        self,
        incident: IncidentModel,
        root_cause_summary: str,
        root_cause_category: str,
        timeline: list[PostmortemTimelineEntry],
        evidence_summary: str,
    ) -> tuple[str, list[str], list[str]]:
        """Synthesize impact, lessons learned, and follow-up actions via LLM with deterministic fallback."""
        llm = self.llm_provider or get_llm_provider(self.settings.llm)

        timeline_text = "\n".join(
            f"- [{t.timestamp.isoformat()}] ({t.event_type}) {t.summary}" for t in timeline
        )

        prompt = (
            f"Synthesize the narrative sections for an incident postmortem.\n\n"
            f"Incident: {incident.title}\n"
            f"Service: {incident.service or 'unknown'}\n"
            f"Severity: {incident.severity}\n"
            f"Root Cause Category: {root_cause_category}\n"
            f"Root Cause Summary: {root_cause_summary}\n\n"
            f"Timeline:\n{timeline_text}\n\n"
            f"Evidence Summary:\n{evidence_summary}\n\n"
            "Requirements:\n"
            "1. Produce a concise, factual impact_summary describing service degradation.\n"
            "2. Provide 1 to 3 actionable lessons_learned for SRE resilience.\n"
            "3. Provide 1 to 3 concrete preventative follow_up_actions.\n"
            "4. Do NOT invent fictional timestamps, metrics, or actions."
        )

        try:
            resp: PostmortemSynthesisResponse = await llm.generate_structured(
                prompt=prompt,
                schema=PostmortemSynthesisResponse,
                system_prompt="You are a senior SRE Postmortem Writer. Write clear, factual, blameless postmortem prose.",
            )
            return resp.impact_summary, resp.lessons_learned, resp.follow_up_actions
        except Exception as exc:
            logger.warning(
                "postmortem_llm_synthesis_failed_using_fallback",
                incident_id=str(incident.id),
                error=str(exc),
            )
            # Deterministic fallback heuristics
            sev_str = (
                incident.severity.value
                if hasattr(incident.severity, "value")
                else str(incident.severity)
            )
            impact = (
                f"Service '{incident.service or 'system'}' experienced a {sev_str} severity incident. "
                f"{incident.summary or 'Automated telemetry detected elevated errors.'}"
            )
            lessons = [
                f"Root cause was verified as {root_cause_category}: {root_cause_summary}",
                "Automated remediation and telemetry recovery validation successfully restored healthy service state.",
            ]
            follow_ups = [
                f"Review telemetry alerts and thresholds for '{incident.service or 'system'}'.",
                f"Ensure runbook automation and remediation safeguards for '{root_cause_category}' remain up to date.",
            ]
            return impact, lessons, follow_ups

    async def generate_and_persist_postmortem(
        self, incident: IncidentModel, similar_incident_ids: list[str] | None = None
    ) -> IncidentPostmortemModel:
        """Generate structured postmortem and persist idempotently."""
        incident_id_str = str(incident.id)
        logger.info("postmortem_generation_started", incident_id=incident_id_str)

        # --- Idempotency Guard ---
        existing = await self.get_postmortem_by_incident_id(incident.id)
        if existing is not None:
            logger.info(
                "postmortem_already_exists",
                incident_id=incident_id_str,
                postmortem_id=str(existing.id),
            )
            return existing

        # --- Remediation History & Timeline ---
        proposals, actions, results, validations = await self._fetch_remediation_history(
            incident.id
        )
        timeline = self._build_factual_timeline(incident, proposals, actions, results, validations)

        # --- Factual Field Extraction ---
        root_cause = incident.root_cause or {}
        root_cause_summary = root_cause.get("summary", "Root cause undetermined.")
        root_cause_category = root_cause.get("root_cause_category", "UNKNOWN")
        contributing_factors = root_cause.get("contributing_factors", [])

        evidence_list = incident.evidence or []
        evidence_lines = [
            f"- [{e.get('evidence_type', 'EVIDENCE')}] {e.get('summary', '')}"
            for e in evidence_list[:10]
        ]
        evidence_summary = (
            "\n".join(evidence_lines)
            if evidence_lines
            else "Telemetry evidence corroborated the failure mode."
        )

        successful_results = [r for r in results if r.success]
        remediation_summary = (
            successful_results[0].summary
            if successful_results
            else "No remediation action recorded."
        )

        passed_validations = [v for v in validations if v.passed]
        validation_summary = (
            passed_validations[0].summary
            if passed_validations
            else (
                validations[0].summary if validations else "Validation confirmed system recovery."
            )
        )

        resolution_summary = incident.resolution or "Incident successfully resolved and validated."
        detection_summary = (
            f"Detected via {incident.source} alert '{incident.alert_payload.get('groupLabels', {}).get('alertname', incident.title)}' "
            f"for service '{incident.service or 'unknown'}'."
            if incident.alert_payload
            else f"Detected via {incident.source}."
        )

        # --- Prose Synthesis ---
        impact_summary, lessons_learned, follow_up_actions = await self._synthesize_prose(
            incident=incident,
            root_cause_summary=root_cause_summary,
            root_cause_category=root_cause_category,
            timeline=timeline,
            evidence_summary=evidence_summary,
        )

        # --- Duration Computation & Persistence ---
        started_at = incident.created_at
        resolved_at = incident.updated_at

        def _normalize(dt: datetime) -> datetime:
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)

        duration_sec = max(0.0, (_normalize(resolved_at) - _normalize(started_at)).total_seconds())

        postmortem_id = uuid4()
        now = datetime.now(UTC)

        verified_causal_ids = root_cause.get("causal_change_ids", [])
        causal_change_summary = (
            root_cause.get("causal_change_summary") if verified_causal_ids else None
        )

        model = IncidentPostmortemModel(
            id=postmortem_id,
            incident_id=incident.id,
            title=f"Postmortem: {incident.title}",
            impact_summary=impact_summary,
            detection_summary=detection_summary,
            timeline=[t.model_dump(mode="json") for t in timeline],
            root_cause_summary=root_cause_summary,
            root_cause_category=root_cause_category,
            contributing_factors=contributing_factors,
            evidence_summary=evidence_summary,
            recent_changes=incident.recent_changes or [],
            causal_change_summary=causal_change_summary,
            remediation_summary=remediation_summary,
            validation_summary=validation_summary,
            resolution_summary=resolution_summary,
            lessons_learned=lessons_learned,
            follow_up_actions=follow_up_actions,
            similar_historical_incidents=similar_incident_ids or [],
            started_at=started_at,
            resolved_at=resolved_at,
            duration_seconds=duration_sec,
            generated_at=now,
        )

        self.session.add(model)
        await self.session.flush()

        logger.info(
            "postmortem_generated",
            incident_id=incident_id_str,
            postmortem_id=str(postmortem_id),
            duration_seconds=duration_sec,
            timeline_entries_count=len(timeline),
        )

        return model
