"""SQLAlchemy ORM model for Incident Memory and pgvector storage."""

from datetime import datetime
from uuid import UUID, uuid4

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from faultwarden.db.base import GUID, Base, TimestampMixin

# Default vector dimensionality (matches default text-embedding-3-small or mock vector dimension)
EMBEDDING_DIMENSION = 384


# --- Incident Memory Model ---
class IncidentMemoryModel(Base, TimestampMixin):
    """Database model for reusable incident memory vectors and contextual summaries."""

    __tablename__ = "incident_memories"

    # --- Core Identifiers ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    incident_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("incidents.id"),
        unique=True,
        nullable=False,
        index=True,
    )

    # --- Contextual Identifiers ---
    service: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # --- Compact Summaries ---
    symptoms_summary: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause_summary: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause_category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    successful_remediation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    successful_action_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    failed_remediation_summaries: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    validation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    resolution_summary: Mapped[str] = mapped_column(Text, nullable=False)

    # --- References & Metrics ---
    postmortem_id: Mapped[UUID | None] = mapped_column(
        GUID(),
        ForeignKey("incident_postmortems.id"),
        nullable=True,
        index=True,
    )
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    incident_duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)

    # --- pgvector Embedding ---
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(EMBEDDING_DIMENSION), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentMemoryModel(id={self.id}, incident_id={self.incident_id}, "
            f"service='{self.service}', classification='{self.classification}')>"
        )
