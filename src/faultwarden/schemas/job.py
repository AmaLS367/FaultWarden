"""Durable investigation job schemas and status definitions."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Job Status Enum ---
class InvestigationJobStatus(StrEnum):
    """Lifecycle status for PostgreSQL-backed durable investigation jobs."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# --- Job API & Service Schemas ---
class InvestigationJobCreate(BaseModel):
    """Payload to enqueue a new durable investigation job."""

    incident_id: UUID
    max_attempts: int = Field(default=3, ge=1)
    available_at: datetime | None = None


class InvestigationJobRead(BaseModel):
    """API and service read model for a durable investigation job."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    status: InvestigationJobStatus
    attempt_count: int
    max_attempts: int
    available_at: datetime
    claimed_at: datetime | None = None
    lease_expires_at: datetime | None = None
    claimed_by: str | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
