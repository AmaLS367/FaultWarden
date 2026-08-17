"""PostgreSQL-backed durable job worker for asynchronous incident investigations."""

import asyncio
import os
import socket
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.config import RemediationSettings, Settings, get_settings
from faultwarden.core.logging import get_logger
from faultwarden.db.models.job import InvestigationJobModel
from faultwarden.db.session import get_session_factory
from faultwarden.schemas.job import InvestigationJobStatus
from faultwarden.services.investigation_service import InvestigationService

logger = get_logger("faultwarden.services.job_worker")


# --- Durable Investigation Job Worker ---
class JobWorker:
    """Consumes and executes durable investigation jobs from PostgreSQL.

    AGENTS.md / Issue 5 Invariants:
    - Replaces in-process FastAPI BackgroundTasks with durable PostgreSQL queue.
    - Uses SELECT ... FOR UPDATE SKIP LOCKED to prevent duplicate processing.
    - Supports bounded retries with exponential backoff on transient errors.
    - Recovers expired leases from crashed or timed-out workers.
    """

    def __init__(
        self,
        session_factory: Any | None = None,
        settings: Settings | None = None,
        worker_id: str | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.remediation_settings: RemediationSettings = self.settings.remediation
        self.session_factory = session_factory or get_session_factory()
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{id(self)}"
        self._running = False

    async def claim_next_job(self, session: AsyncSession) -> InvestigationJobModel | None:
        """Atomically claim the next eligible job for execution using FOR UPDATE SKIP LOCKED.

        Claims jobs that are:
        1. PENDING and available_at <= now, OR
        2. RUNNING and lease_expires_at < now (expired lease recovery) with attempt_count < max_attempts.
        """
        now = datetime.now(UTC)

        # Build eligibility query
        stmt = (
            select(InvestigationJobModel)
            .where(
                or_(
                    (InvestigationJobModel.status == InvestigationJobStatus.PENDING)
                    & (InvestigationJobModel.available_at <= now),
                    (InvestigationJobModel.status == InvestigationJobStatus.RUNNING)
                    & (InvestigationJobModel.lease_expires_at < now)
                    & (InvestigationJobModel.attempt_count < InvestigationJobModel.max_attempts),
                )
            )
            .order_by(InvestigationJobModel.available_at.asc())
            .limit(1)
        )

        # Check dialect to safely apply SKIP LOCKED only on PostgreSQL
        bind = session.get_bind()
        dialect_name = bind.dialect.name if bind is not None else "postgresql"
        if dialect_name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)

        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if job is None:
            return None

        # Transition claimed job to RUNNING with lease
        lease_seconds = self.remediation_settings.job_lease_seconds
        job.status = InvestigationJobStatus.RUNNING
        job.claimed_at = now
        job.claimed_by = self.worker_id
        job.lease_expires_at = now + timedelta(seconds=lease_seconds)
        job.attempt_count += 1

        await session.commit()
        await session.refresh(job)

        logger.info(
            "job_claimed",
            job_id=str(job.id),
            incident_id=str(job.incident_id),
            attempt=job.attempt_count,
            max_attempts=job.max_attempts,
            worker_id=self.worker_id,
            lease_expires_at=job.lease_expires_at.isoformat() if job.lease_expires_at else None,
        )
        return job

    async def process_job(
        self,
        job_id: UUID,
        *,
        investigation_service: InvestigationService | None = None,
    ) -> bool:
        """Execute the investigation graph for a claimed job with error handling and retry scheduling."""
        async with self.session_factory() as session:
            job_stmt = select(InvestigationJobModel).where(InvestigationJobModel.id == job_id)
            res = await session.execute(job_stmt)
            job = res.scalar_one_or_none()
            if job is None:
                logger.error("job_not_found_for_processing", job_id=str(job_id))
                return False

            incident_id = job.incident_id

        logger.info(
            "job_execution_started",
            job_id=str(job_id),
            incident_id=str(incident_id),
        )

        success = False
        error_msg: str | None = None

        try:
            inv_svc = investigation_service or InvestigationService(
                settings=self.settings,
                session_factory=self.session_factory,
            )
            await inv_svc.run_investigation(incident_id)
            success = True
            logger.info("job_execution_succeeded", job_id=str(job_id), incident_id=str(incident_id))
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            logger.error(
                "job_execution_failed",
                job_id=str(job_id),
                incident_id=str(incident_id),
                error=error_msg,
                exc_info=True,
            )

        # Update job status in a new transaction
        async with self.session_factory() as session:
            job_stmt = select(InvestigationJobModel).where(InvestigationJobModel.id == job_id)
            res = await session.execute(job_stmt)
            job = res.scalar_one_or_none()
            if job is None:
                return success

            now = datetime.now(UTC)
            if success:
                job.status = InvestigationJobStatus.COMPLETED
                job.completed_at = now
                job.last_error = None
            else:
                job.last_error = error_msg
                if job.attempt_count < job.max_attempts:
                    # Retry with exponential backoff (e.g. 2, 4, 8 seconds)
                    backoff_sec = 2**job.attempt_count
                    job.status = InvestigationJobStatus.PENDING
                    job.available_at = now + timedelta(seconds=backoff_sec)
                    logger.info(
                        "job_scheduled_for_retry",
                        job_id=str(job.id),
                        attempt=job.attempt_count,
                        retry_in_seconds=backoff_sec,
                    )
                else:
                    job.status = InvestigationJobStatus.FAILED
                    job.completed_at = now
                    logger.error(
                        "job_permanently_failed",
                        job_id=str(job.id),
                        attempt=job.attempt_count,
                        max_attempts=job.max_attempts,
                    )

            await session.commit()

        return success

    async def run_once(self) -> bool:
        """Check for and process a single job. Returns True if a job was processed, False otherwise."""
        async with self.session_factory() as session:
            job = await self.claim_next_job(session)

        if job is None:
            return False

        await self.process_job(job.id)
        return True

    async def run_loop(self) -> None:
        """Continuous worker execution loop."""
        self._running = True
        poll_interval = self.remediation_settings.worker_poll_interval_seconds
        logger.info(
            "job_worker_started",
            worker_id=self.worker_id,
            poll_interval=poll_interval,
        )

        while self._running:
            try:
                processed = await self.run_once()
                if not processed:
                    await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                logger.info("job_worker_cancelled", worker_id=self.worker_id)
                self._running = False
                break
            except Exception as exc:
                logger.error("job_worker_unexpected_error", error=str(exc), exc_info=True)
                await asyncio.sleep(poll_interval)

    def stop(self) -> None:
        """Signal the worker loop to stop gracefully."""
        self._running = False
