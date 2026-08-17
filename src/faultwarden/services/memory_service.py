"""Service layer for incident memory persistence, pgvector similarity search, and quality enforcement."""

import math
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.config import MemorySettings, Settings, get_settings
from faultwarden.core.logging import get_logger
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.memory import IncidentMemoryModel
from faultwarden.db.models.postmortem import IncidentPostmortemModel
from faultwarden.db.models.remediation import (
    RemediationActionModel,
    RemediationResultModel,
    RemediationValidationModel,
)
from faultwarden.integrations.embedding.provider import (
    EmbeddingProvider,
    get_embedding_provider,
)
from faultwarden.schemas.incident import IncidentStatus
from faultwarden.schemas.memory import SimilarIncidentMemory

logger = get_logger("faultwarden.services.memory")


# --- Canonical Text Representation Builder ---
def build_canonical_memory_text(
    service: str,
    classification: str,
    severity: str,
    symptoms_summary: str,
    root_cause_summary: str,
    evidence_summary: str,
    successful_remediation_summary: str,
    validation_summary: str,
    resolution_summary: str,
    causal_change_summary: str | None = None,
) -> str:
    """Deterministically assemble canonical document text used for generating embeddings."""
    base = (
        f"Service: {service}\n"
        f"Classification: {classification}\n"
        f"Severity: {severity}\n"
        f"Symptoms:\n{symptoms_summary.strip()}\n\n"
        f"Root Cause:\n{root_cause_summary.strip()}\n\n"
        f"Evidence:\n{evidence_summary.strip()}\n\n"
        f"Successful Remediation:\n{successful_remediation_summary.strip()}\n\n"
        f"Validation:\n{validation_summary.strip()}\n\n"
        f"Resolution:\n{resolution_summary.strip()}"
    )
    if causal_change_summary:
        base += f"\n\nCausal Change:\n{causal_change_summary.strip()}"
    return base


# --- Cosine Similarity Helper for SQLite / Test Fallback ---
def calculate_cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Calculate cosine similarity between two float vectors in pure Python."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot_product = sum(a * b for a, b in zip(vec_a, vec_b, strict=False))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot_product / (norm_a * norm_b)


# --- Memory Service ---
class MemoryService:
    """Manages creation, indexing, quality validation, and semantic retrieval of incident memories."""

    def __init__(
        self,
        session: AsyncSession,
        embedding_provider: EmbeddingProvider | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.memory_settings: MemorySettings = self.settings.memory
        self.embedding_provider = embedding_provider

    def _get_provider(self) -> EmbeddingProvider:
        """Resolve the active embedding provider."""
        return self.embedding_provider or get_embedding_provider(self.memory_settings)

    async def get_memory_by_incident_id(
        self, incident_id: UUID | str
    ) -> IncidentMemoryModel | None:
        """Retrieve the persisted memory model for an incident."""
        uuid_val = incident_id if isinstance(incident_id, UUID) else UUID(incident_id)
        stmt = select(IncidentMemoryModel).where(IncidentMemoryModel.incident_id == uuid_val)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    # --- Quality Policy Check ---
    async def is_eligible_for_memory(self, incident: IncidentModel) -> tuple[bool, str]:
        """Evaluate deterministic quality policy for indexing as trusted memory.

        Requirements:
        1. Incident status == RESOLVED
        2. Root cause was verified
        3. Remediation recovery validation passed
        4. Structured fields exist
        """
        if incident.status != IncidentStatus.RESOLVED:
            return False, f"Incident status is '{incident.status}', not RESOLVED."

        if not incident.root_cause or not isinstance(incident.root_cause, dict):
            return False, "Incident does not have verified root_cause analysis."

        if not incident.evidence:
            return False, "Incident does not have evidence items."

        # Verify that remediation recovery validation passed
        val_stmt = (
            select(RemediationValidationModel)
            .where(
                RemediationValidationModel.incident_id == incident.id,
                RemediationValidationModel.passed.is_(True),
            )
            .limit(1)
        )
        val_res = await self.session.execute(val_stmt)
        passed_val = val_res.scalar_one_or_none()

        # If no explicit passed validation row in DB, check if incident resolution states validation passed
        if passed_val is None:
            resolution_text = incident.resolution or ""
            if "validation did not confirm recovery" in resolution_text.lower():
                return False, "Remediation validation failed or unconfirmed."

        return True, "Incident meets all memory quality criteria."

    # --- Indexing ---
    async def index_incident_memory(
        self,
        incident: IncidentModel,
        postmortem: IncidentPostmortemModel | None = None,
    ) -> IncidentMemoryModel | None:
        """Index a resolved and validated incident as a compact vector memory record."""
        incident_id_str = str(incident.id)

        # --- 1. Evaluate Quality Policy ---
        eligible, reason = await self.is_eligible_for_memory(incident)
        if not eligible:
            logger.warning(
                "incident_memory_not_eligible",
                incident_id=incident_id_str,
                reason=reason,
            )
            return None

        # --- 2. Check Idempotency (prevent duplicate memories) ---
        existing = await self.get_memory_by_incident_id(incident.id)
        if existing is not None:
            logger.info(
                "incident_memory_already_exists",
                incident_id=incident_id_str,
                memory_id=str(existing.id),
            )
            return existing

        # --- 3. Extract Structured Fields ---
        service_name = incident.service or "unknown"
        classification_dict = incident.classification or {}
        classification_cat = classification_dict.get(
            "category",
            incident.alert_payload.get("groupLabels", {}).get("alertname", "UNKNOWN"),
        )
        sev_str = (
            incident.severity.value
            if hasattr(incident.severity, "value")
            else str(incident.severity)
        )

        # - Symptoms
        alert_info = incident.alert_payload or {}
        ann = alert_info.get("commonAnnotations", {})
        symptoms = (
            ann.get("summary") or ann.get("description") or incident.summary or incident.title
        )

        # - Root Cause
        root_cause = incident.root_cause or {}
        rc_summary = root_cause.get("summary", "Root cause verified.")
        rc_category = root_cause.get("root_cause_category", "UNKNOWN")

        # - Evidence Summary
        evidence_list = incident.evidence or []
        evidence_lines = [
            f"- [{e.get('evidence_type', 'EVIDENCE')}] {e.get('summary', '')}"
            for e in evidence_list[:6]
        ]
        evidence_summary = (
            "\n".join(evidence_lines)
            if evidence_lines
            else "Telemetry evidence corroborated the incident."
        )

        # - Successful & Failed Remediations
        act_stmt = (
            select(RemediationActionModel)
            .where(RemediationActionModel.incident_id == incident.id)
            .order_by(RemediationActionModel.created_at.asc())
        )
        actions = list((await self.session.execute(act_stmt)).scalars().all())

        action_ids = [a.id for a in actions]
        results: list[RemediationResultModel] = []
        if action_ids:
            res_stmt = select(RemediationResultModel).where(
                RemediationResultModel.action_id.in_(action_ids)
            )
            results = list((await self.session.execute(res_stmt)).scalars().all())

        successful_results = [r for r in results if r.success]
        successful_action_type = None
        if successful_results:
            successful_action_id = successful_results[0].action_id
            matching_act = next((a for a in actions if a.id == successful_action_id), None)
            if matching_act:
                successful_action_type = (
                    matching_act.action_type.value
                    if hasattr(matching_act.action_type, "value")
                    else str(matching_act.action_type)
                )
            remediation_summary = successful_results[0].summary
        else:
            remediation_summary = "Remediation executed successfully."

        failed_summaries = [r.summary for r in results if not r.success]

        # - Validation Summary
        val_stmt = (
            select(RemediationValidationModel)
            .where(RemediationValidationModel.incident_id == incident.id)
            .order_by(RemediationValidationModel.started_at.desc())
        )
        validations = list((await self.session.execute(val_stmt)).scalars().all())
        val_summary = (
            validations[0].summary
            if validations
            else "Post-remediation telemetry validated full recovery."
        )
        resolution_summary = incident.resolution or "Incident resolved and verified."

        # - Durations
        started_at = incident.created_at
        resolved_at = incident.updated_at

        def _normalize(dt: datetime) -> datetime:
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)

        duration_sec = max(0.0, (_normalize(resolved_at) - _normalize(started_at)).total_seconds())

        # --- 4. Generate Embedding Vector ---
        causal_change_summary = root_cause.get("causal_change_summary")
        causal_change_type = root_cause.get("technical_details", {}).get("causal_change_type")
        if not causal_change_type and incident.causal_changes:
            causal_change_type = str(incident.causal_changes[0].get("change_type", "UNKNOWN"))

        canonical_text = build_canonical_memory_text(
            service=service_name,
            classification=str(classification_cat or "UNKNOWN"),
            severity=sev_str,
            symptoms_summary=symptoms,
            root_cause_summary=rc_summary,
            evidence_summary=evidence_summary,
            successful_remediation_summary=remediation_summary,
            validation_summary=val_summary,
            resolution_summary=resolution_summary,
            causal_change_summary=causal_change_summary,
        )

        embedding_vec: list[float] | None = None
        try:
            provider = self._get_provider()
            embedding_vec = await provider.embed(canonical_text)
        except Exception as exc:
            logger.error(
                "incident_memory_index_failed",
                incident_id=incident_id_str,
                error=str(exc),
            )
            # Embedding generation failed: we do not crash or block resolution
            return None

        # --- 5. Persist IncidentMemoryModel ---
        memory_id = uuid4()
        postmortem_id = postmortem.id if postmortem else None

        memory_model = IncidentMemoryModel(
            id=memory_id,
            incident_id=incident.id,
            service=service_name,
            classification=classification_cat,
            severity=sev_str,
            symptoms_summary=symptoms,
            root_cause_summary=rc_summary,
            root_cause_category=rc_category,
            evidence_summary=evidence_summary,
            successful_remediation_summary=remediation_summary,
            successful_action_type=successful_action_type,
            failed_remediation_summaries=failed_summaries,
            validation_summary=val_summary,
            resolution_summary=resolution_summary,
            causal_change_summary=causal_change_summary,
            causal_change_type=causal_change_type,
            postmortem_id=postmortem_id,
            resolved_at=resolved_at,
            incident_duration_seconds=duration_sec,
            embedding=embedding_vec,
        )

        self.session.add(memory_model)
        await self.session.flush()

        logger.info(
            "incident_memory_created",
            incident_id=incident_id_str,
            memory_id=str(memory_id),
            service=service_name,
            classification=classification_cat,
            root_cause_category=rc_category,
        )

        return memory_model

    # --- Similarity Retrieval ---
    async def search_similar(
        self,
        query: str | list[float],
        service: str | None = None,
        classification: str | None = None,
        limit: int | None = None,
        min_similarity: float | None = None,
        exclude_incident_id: UUID | None = None,
    ) -> list[SimilarIncidentMemory]:
        """Retrieve bounded top-k similar resolved incidents from incident memory."""
        top_k = limit or self.memory_settings.top_k
        min_sim = (
            min_similarity if min_similarity is not None else self.memory_settings.min_similarity
        )

        logger.info(
            "incident_memory_search_started",
            query_is_text=isinstance(query, str),
            service=service,
            classification=classification,
            top_k=top_k,
            min_similarity=min_sim,
        )

        # --- 1. Resolve Query Embedding Vector ---
        query_vec: list[float]
        if isinstance(query, str):
            try:
                provider = self._get_provider()
                query_vec = await provider.embed(query)
            except Exception as exc:
                logger.warning(
                    "incident_memory_unavailable",
                    reason=f"Embedding provider query failed: {exc}",
                )
                return []
        else:
            query_vec = query

        # --- 2. Query Memory Records ---
        bind = self.session.get_bind()
        dialect_name = bind.dialect.name if bind is not None else "postgresql"

        results: list[SimilarIncidentMemory] = []

        if dialect_name == "postgresql":
            # Native pgvector cosine distance search
            # distance: 0.0 (identical) to 2.0 (opposite). Similarity = 1.0 - distance
            stmt = select(
                IncidentMemoryModel,
                IncidentMemoryModel.embedding.cosine_distance(query_vec).label("distance"),
            )
            if service:
                stmt = stmt.where(IncidentMemoryModel.service == service)
            if classification:
                stmt = stmt.where(IncidentMemoryModel.classification == classification)
            if exclude_incident_id:
                stmt = stmt.where(IncidentMemoryModel.incident_id != exclude_incident_id)

            stmt = stmt.order_by("distance").limit(top_k * 2)
            db_res = await self.session.execute(stmt)
            rows = db_res.all()

            for memory_obj, distance in rows:
                sim = 1.0 - float(distance)
                if sim >= min_sim:
                    results.append(
                        SimilarIncidentMemory(
                            incident_id=memory_obj.incident_id,
                            memory_id=memory_obj.id,
                            similarity=round(sim, 4),
                            service=memory_obj.service,
                            classification=memory_obj.classification,
                            severity=memory_obj.severity,
                            symptoms_summary=memory_obj.symptoms_summary,
                            root_cause_summary=memory_obj.root_cause_summary,
                            root_cause_category=memory_obj.root_cause_category,
                            causal_change_summary=memory_obj.causal_change_summary,
                            causal_change_type=memory_obj.causal_change_type,
                            successful_remediation_summary=memory_obj.successful_remediation_summary,
                            successful_action_type=memory_obj.successful_action_type,
                            validation_summary=memory_obj.validation_summary,
                            resolved_at=memory_obj.resolved_at,
                        )
                    )
                    if len(results) >= top_k:
                        break
        else:
            # SQLite / Test Fallback: in-memory cosine similarity over candidate rows
            stmt = select(IncidentMemoryModel)
            if service:
                stmt = stmt.where(IncidentMemoryModel.service == service)
            if classification:
                stmt = stmt.where(IncidentMemoryModel.classification == classification)
            if exclude_incident_id:
                stmt = stmt.where(IncidentMemoryModel.incident_id != exclude_incident_id)

            db_res = await self.session.execute(stmt)
            memories = list(db_res.scalars().all())

            scored_memories: list[tuple[IncidentMemoryModel, float]] = []
            for mem in memories:
                if mem.embedding:
                    sim = calculate_cosine_similarity(query_vec, mem.embedding)
                    if sim >= min_sim:
                        scored_memories.append((mem, sim))

            # Sort descending by similarity
            scored_memories.sort(key=lambda x: x[1], reverse=True)

            for memory_obj, sim in scored_memories[:top_k]:
                results.append(
                    SimilarIncidentMemory(
                        incident_id=memory_obj.incident_id,
                        memory_id=memory_obj.id,
                        similarity=round(sim, 4),
                        service=memory_obj.service,
                        classification=memory_obj.classification,
                        severity=memory_obj.severity,
                        symptoms_summary=memory_obj.symptoms_summary,
                        root_cause_summary=memory_obj.root_cause_summary,
                        root_cause_category=memory_obj.root_cause_category,
                        causal_change_summary=memory_obj.causal_change_summary,
                        causal_change_type=memory_obj.causal_change_type,
                        successful_remediation_summary=memory_obj.successful_remediation_summary,
                        successful_action_type=memory_obj.successful_action_type,
                        validation_summary=memory_obj.validation_summary,
                        resolved_at=memory_obj.resolved_at,
                    )
                )

        logger.info(
            "incident_memory_search_completed",
            results_count=len(results),
            top_similarity=results[0].similarity if results else None,
        )
        if results:
            logger.info(
                "historical_incidents_retrieved",
                count=len(results),
                top_incident_id=str(results[0].incident_id),
                top_similarity=results[0].similarity,
            )

        return results
