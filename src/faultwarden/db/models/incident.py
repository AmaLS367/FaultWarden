"""SQLAlchemy ORM model for Incident entity."""

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column

from faultwarden.db.base import GUID, Base, TimestampMixin
from faultwarden.schemas.incident import IncidentSeverity, IncidentStatus


class IncidentModel(Base, TimestampMixin):
    """Database model for an incident."""

    __tablename__ = "incidents"

    # --- Core Incident Attributes ---
    id: Mapped[UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid4,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[IncidentStatus] = mapped_column(
        SQLEnum(IncidentStatus, name="incident_status", native_enum=False),
        nullable=False,
        default=IncidentStatus.DETECTED,
        index=True,
    )
    severity: Mapped[IncidentSeverity] = mapped_column(
        SQLEnum(IncidentSeverity, name="incident_severity", native_enum=False),
        nullable=False,
        default=IncidentSeverity.MEDIUM,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(100), nullable=False, default="alertmanager", index=True
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Correlating Identifiers & Alert Lifecycle ---
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    service: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    alert_status: Mapped[str | None] = mapped_column(
        String(30), nullable=True, default="firing", index=True
    )

    # --- Structured JSON Payloads & Investigation State ---
    alert_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    hypotheses: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    root_cause: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    proposed_remediations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<IncidentModel(id={self.id}, title='{self.title}', status='{self.status}', severity='{self.severity}')>"
