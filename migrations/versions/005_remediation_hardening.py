"""add investigation_jobs, remediation_validations, and action idempotency

Revision ID: 005_remediation_hardening
Revises: 004_add_remediation_tables
Create Date: 2026-08-16 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from faultwarden.db.base import GUID

# revision identifiers, used by Alembic.
revision: str = "005_remediation_hardening"
down_revision: str | None = "004_add_remediation_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add idempotency_key and claim_expires_at to remediation_actions
    op.add_column(
        "remediation_actions",
        sa.Column("idempotency_key", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "remediation_actions",
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        op.f("ix_remediation_actions_idempotency_key"),
        "remediation_actions",
        ["idempotency_key"],
        unique=True,
    )

    # 2. Create remediation_validations table
    op.create_table(
        "remediation_validations",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column(
            "action_id",
            GUID(),
            sa.ForeignKey("remediation_actions.id"),
            nullable=False,
        ),
        sa.Column("incident_id", GUID(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        op.f("ix_remediation_validations_action_id"),
        "remediation_validations",
        ["action_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_remediation_validations_incident_id"),
        "remediation_validations",
        ["incident_id"],
        unique=False,
    )

    # 3. Create investigation_jobs table
    op.create_table(
        "investigation_jobs",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column("incident_id", GUID(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.String(length=100), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        op.f("ix_investigation_jobs_incident_id"),
        "investigation_jobs",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_investigation_jobs_status_available_at"),
        "investigation_jobs",
        ["status", "available_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_investigation_jobs_status_lease_expires_at"),
        "investigation_jobs",
        ["status", "lease_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    # Drop investigation_jobs
    op.drop_index(
        op.f("ix_investigation_jobs_status_lease_expires_at"),
        table_name="investigation_jobs",
    )
    op.drop_index(
        op.f("ix_investigation_jobs_status_available_at"),
        table_name="investigation_jobs",
    )
    op.drop_index(op.f("ix_investigation_jobs_incident_id"), table_name="investigation_jobs")
    op.drop_table("investigation_jobs")

    # Drop remediation_validations
    op.drop_index(
        op.f("ix_remediation_validations_incident_id"),
        table_name="remediation_validations",
    )
    op.drop_index(
        op.f("ix_remediation_validations_action_id"),
        table_name="remediation_validations",
    )
    op.drop_table("remediation_validations")

    # Drop columns from remediation_actions
    op.drop_index(
        op.f("ix_remediation_actions_idempotency_key"),
        table_name="remediation_actions",
    )
    op.drop_column("remediation_actions", "claim_expires_at")
    op.drop_column("remediation_actions", "idempotency_key")
