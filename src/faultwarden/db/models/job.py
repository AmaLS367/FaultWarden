"""SQLAlchemy ORM model for durable investigation jobs."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column

from faultwarden.db.base import GUID, Base, TimestampMixin
from faultwarden.schemas.job import InvestigationJobStatus


# --- Investigation Job Model ---
class InvestigationJobModel(Base, TimestampMixin):
    """Database model for PostgreSQL-backed durable investigation jobs."""

    __tablename__ = "investigation_jobs"

    # --- Core Identifiers ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    incident_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )

    # --- Job Lifecycle & Lease State ---
    status: Mapped[InvestigationJobStatus] = mapped_column(
        SQLEnum(InvestigationJobStatus, name="investigation_job_status", native_enum=False),
        nullable=False,
        default=InvestigationJobStatus.PENDING,
        index=True,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    claimed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<InvestigationJobModel(id={self.id}, incident_id={self.incident_id}, "
            f"status='{self.status}', attempt={self.attempt_count}/{self.max_attempts})>"
        )
