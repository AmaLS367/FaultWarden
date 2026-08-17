"""add incident_postmortems and incident_memories with pgvector support

Revision ID: 006_incident_memory
Revises: 005_remediation_hardening
Create Date: 2026-08-17 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

from faultwarden.db.base import GUID

# revision identifiers, used by Alembic.
# Kept short: alembic_version.version_num is VARCHAR(32) and cannot fit the
# full descriptive slug.
revision: str = "006_incident_memory"
down_revision: str | None = "005_remediation_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 0. Safely enable pgvector extension on PostgreSQL
    bind = op.get_bind()
    dialect_name = bind.dialect.name if bind is not None else "postgresql"
    if dialect_name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # 1. Create incident_postmortems table
    op.create_table(
        "incident_postmortems",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            GUID(),
            sa.ForeignKey("incidents.id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("impact_summary", sa.Text(), nullable=False),
        sa.Column("detection_summary", sa.Text(), nullable=False),
        sa.Column("timeline", sa.JSON(), nullable=False),
        sa.Column("root_cause_summary", sa.Text(), nullable=False),
        sa.Column("root_cause_category", sa.String(length=100), nullable=False),
        sa.Column("contributing_factors", sa.JSON(), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("remediation_summary", sa.Text(), nullable=False),
        sa.Column("validation_summary", sa.Text(), nullable=False),
        sa.Column("resolution_summary", sa.Text(), nullable=False),
        sa.Column("lessons_learned", sa.JSON(), nullable=False),
        sa.Column("follow_up_actions", sa.JSON(), nullable=False),
        sa.Column("similar_historical_incidents", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        op.f("ix_incident_postmortems_incident_id"),
        "incident_postmortems",
        ["incident_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_incident_postmortems_root_cause_category"),
        "incident_postmortems",
        ["root_cause_category"],
        unique=False,
    )

    # 2. Create incident_memories table
    op.create_table(
        "incident_memories",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            GUID(),
            sa.ForeignKey("incidents.id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("service", sa.String(length=100), nullable=False),
        sa.Column("classification", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("symptoms_summary", sa.Text(), nullable=False),
        sa.Column("root_cause_summary", sa.Text(), nullable=False),
        sa.Column("root_cause_category", sa.String(length=100), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("successful_remediation_summary", sa.Text(), nullable=False),
        sa.Column("successful_action_type", sa.String(length=100), nullable=True),
        sa.Column("failed_remediation_summaries", sa.JSON(), nullable=False),
        sa.Column("validation_summary", sa.Text(), nullable=False),
        sa.Column("resolution_summary", sa.Text(), nullable=False),
        sa.Column(
            "postmortem_id",
            GUID(),
            sa.ForeignKey("incident_postmortems.id"),
            nullable=True,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_duration_seconds", sa.Float(), nullable=False),
        sa.Column("embedding", Vector(384), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        op.f("ix_incident_memories_incident_id"),
        "incident_memories",
        ["incident_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_incident_memories_service"),
        "incident_memories",
        ["service"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_memories_classification"),
        "incident_memories",
        ["classification"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_memories_root_cause_category"),
        "incident_memories",
        ["root_cause_category"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_incident_memories_root_cause_category"), table_name="incident_memories")
    op.drop_index(op.f("ix_incident_memories_classification"), table_name="incident_memories")
    op.drop_index(op.f("ix_incident_memories_service"), table_name="incident_memories")
    op.drop_index(op.f("ix_incident_memories_incident_id"), table_name="incident_memories")
    op.drop_table("incident_memories")

    op.drop_index(
        op.f("ix_incident_postmortems_root_cause_category"),
        table_name="incident_postmortems",
    )
    op.drop_index(op.f("ix_incident_postmortems_incident_id"), table_name="incident_postmortems")
    op.drop_table("incident_postmortems")
