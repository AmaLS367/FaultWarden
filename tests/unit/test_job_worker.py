"""Unit tests for durable PostgreSQL job worker (Issue 5).

Invariants:
- Atomic claim via SELECT ... FOR UPDATE SKIP LOCKED (or SQLite transaction locking).
- Lease management and lease expiry recovery.
- Bounded retries (job_max_attempts).
- Exponential backoff on retries.
- Failed attempts increment attempt count; terminal failures transition to FAILED.
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.core.config import RemediationSettings, Settings
from faultwarden.db.models.incident import IncidentModel
from faultwarden.db.models.job import InvestigationJobModel
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus
from faultwarden.schemas.job import InvestigationJobStatus
from faultwarden.services.job_worker import JobWorker


async def _create_test_incident_and_job(
    db_session: AsyncSession,
    *,
    status: InvestigationJobStatus = InvestigationJobStatus.PENDING,
    attempts: int = 0,
    lease_expired: bool = False,
) -> tuple[IncidentModel, InvestigationJobModel]:
    incident = IncidentModel(
        id=uuid4(),
        title="[CRITICAL] Job Worker Test Incident",
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.CRITICAL,
        source="alertmanager",
        fingerprint=f"fp-job-{uuid4()}",
        service="demo-service",
        alert_payload={},
    )
    db_session.add(incident)
    await db_session.flush()

    now = datetime.now(UTC)
    lease_expires = now - timedelta(seconds=10) if lease_expired else now + timedelta(seconds=60)

    job = InvestigationJobModel(
        id=uuid4(),
        incident_id=incident.id,
        status=status,
        attempt_count=attempts,
        max_attempts=3,
        claimed_by="worker-test" if status == InvestigationJobStatus.RUNNING else None,
        claimed_at=now if status == InvestigationJobStatus.RUNNING else None,
        lease_expires_at=lease_expires if status == InvestigationJobStatus.RUNNING else None,
    )
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)
    return incident, job


@pytest.mark.asyncio
async def test_worker_claims_pending_job(db_session: AsyncSession) -> None:
    """Worker claims a PENDING job and marks it RUNNING with worker_id and lease."""
    _incident, job = await _create_test_incident_and_job(
        db_session, status=InvestigationJobStatus.PENDING
    )

    worker = JobWorker(
        settings=Settings(
            remediation=RemediationSettings(job_lease_seconds=30, job_max_attempts=3)
        ),
        worker_id="worker-node-1",
    )

    claimed_job = await worker.claim_next_job(db_session)
    assert claimed_job is not None
    assert claimed_job.id == job.id
    assert claimed_job.status == InvestigationJobStatus.RUNNING
    assert claimed_job.claimed_by == "worker-node-1"
    assert claimed_job.attempt_count == 1
    assert claimed_job.lease_expires_at is not None


@pytest.mark.asyncio
async def test_worker_reclaims_expired_lease_job(db_session: AsyncSession) -> None:
    """Worker reclaims a RUNNING job whose lease has expired."""
    _incident, job = await _create_test_incident_and_job(
        db_session,
        status=InvestigationJobStatus.RUNNING,
        attempts=1,
        lease_expired=True,
    )

    worker = JobWorker(
        settings=Settings(
            remediation=RemediationSettings(job_lease_seconds=30, job_max_attempts=3)
        ),
        worker_id="worker-node-2",
    )

    reclaimed_job = await worker.claim_next_job(db_session)
    assert reclaimed_job is not None
    assert reclaimed_job.id == job.id
    assert reclaimed_job.claimed_by == "worker-node-2"
    assert reclaimed_job.attempt_count == 2


@pytest.mark.asyncio
async def test_worker_marks_job_completed_on_success(db_session: AsyncSession) -> None:
    """Successful investigation marks job as COMPLETED."""
    _incident, job = await _create_test_incident_and_job(
        db_session, status=InvestigationJobStatus.PENDING
    )

    @asynccontextmanager
    async def fake_factory():
        yield db_session

    worker = JobWorker(
        settings=Settings(),
        session_factory=fake_factory,
        worker_id="worker-node-3",
    )

    # Mock investigation service execution
    mock_inv_service = AsyncMock()
    mock_inv_service.run_investigation = AsyncMock()

    claimed_job = await worker.claim_next_job(db_session)
    assert claimed_job is not None

    await worker.process_job(claimed_job.id, investigation_service=mock_inv_service)

    stmt = select(InvestigationJobModel).where(InvestigationJobModel.id == job.id)
    res = await db_session.execute(stmt)
    refreshed_job = res.scalar_one()
    assert refreshed_job.status == InvestigationJobStatus.COMPLETED
    assert refreshed_job.completed_at is not None


@pytest.mark.asyncio
async def test_worker_retries_transient_failure_with_backoff(db_session: AsyncSession) -> None:
    """Job that fails before max_attempts transitions back to PENDING with available_at set."""
    _incident, job = await _create_test_incident_and_job(
        db_session,
        status=InvestigationJobStatus.PENDING,
        attempts=0,
    )

    @asynccontextmanager
    async def fake_factory():
        yield db_session

    worker = JobWorker(
        settings=Settings(remediation=RemediationSettings(job_max_attempts=3)),
        session_factory=fake_factory,
        worker_id="worker-node-4",
    )

    mock_inv_service = AsyncMock()
    mock_inv_service.run_investigation.side_effect = Exception("Transient database timeout")

    claimed_job = await worker.claim_next_job(db_session)
    assert claimed_job is not None

    await worker.process_job(claimed_job.id, investigation_service=mock_inv_service)

    stmt = select(InvestigationJobModel).where(InvestigationJobModel.id == job.id)
    res = await db_session.execute(stmt)
    refreshed_job = res.scalar_one()

    assert refreshed_job.status == InvestigationJobStatus.PENDING
    assert refreshed_job.last_error is not None
    assert "Transient database timeout" in refreshed_job.last_error
    assert refreshed_job.available_at is not None


@pytest.mark.asyncio
async def test_worker_marks_job_failed_after_max_attempts(db_session: AsyncSession) -> None:
    """Job that fails and reaches max_attempts transitions terminally to FAILED."""
    _incident, job = await _create_test_incident_and_job(
        db_session,
        status=InvestigationJobStatus.PENDING,
        attempts=2,  # next attempt will be 3 == max_attempts
    )

    @asynccontextmanager
    async def fake_factory():
        yield db_session

    worker = JobWorker(
        settings=Settings(remediation=RemediationSettings(job_max_attempts=3)),
        session_factory=fake_factory,
        worker_id="worker-node-5",
    )

    mock_inv_service = AsyncMock()
    mock_inv_service.run_investigation.side_effect = Exception(
        "Permanent graph configuration failure"
    )

    claimed_job = await worker.claim_next_job(db_session)
    assert claimed_job is not None
    assert claimed_job.attempt_count == 3

    await worker.process_job(claimed_job.id, investigation_service=mock_inv_service)

    stmt = select(InvestigationJobModel).where(InvestigationJobModel.id == job.id)
    res = await db_session.execute(stmt)
    refreshed_job = res.scalar_one()

    assert refreshed_job.status == InvestigationJobStatus.FAILED
    assert refreshed_job.completed_at is not None
    assert "Permanent graph configuration failure" in (refreshed_job.last_error or "")
