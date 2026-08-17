"""SQLAlchemy ORM model for Incident Postmortem documents."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from faultwarden.db.base import GUID, Base, TimestampMixin


# --- Incident Postmortem Model ---
class IncidentPostmortemModel(Base, TimestampMixin):
    """Database model for structured postmortems generated after incident resolution."""

    __tablename__ = "incident_postmortems"

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

    # --- Header & Impact ---
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    impact_summary: Mapped[str] = mapped_column(Text, nullable=False)
    detection_summary: Mapped[str] = mapped_column(Text, nullable=False)

    # --- Factual Timeline ---
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    # --- Root Cause & Evidence ---
    root_cause_summary: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause_category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    contributing_factors: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    recent_changes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    causal_change_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Remediation & Validation ---
    remediation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    validation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    resolution_summary: Mapped[str] = mapped_column(Text, nullable=False)

    # --- Follow-Up & Learning ---
    lessons_learned: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    follow_up_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    similar_historical_incidents: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )

    # --- Time Metrics ---
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    def __repr__(self) -> str:
        return f"<IncidentPostmortemModel(id={self.id}, incident_id={self.incident_id}, title='{self.title}')>"
