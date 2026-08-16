"""add remediation tables and langgraph_thread_id

Revision ID: 004_add_remediation_tables
Revises: 003_add_investigation_metadata
Create Date: 2026-08-16 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from faultwarden.db.base import GUID

# revision identifiers, used by Alembic.
revision: str = "004_add_remediation_tables"
down_revision: str | None = "003_add_investigation_metadata"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add langgraph_thread_id column to incidents
    op.add_column(
        "incidents",
        sa.Column("langgraph_thread_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f("ix_incidents_langgraph_thread_id"),
        "incidents",
        ["langgraph_thread_id"],
        unique=False,
    )

    # Create remediation_proposals table
    op.create_table(
        "remediation_proposals",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column("incident_id", GUID(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("action_type", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("expected_effect", sa.Text(), nullable=False),
        sa.Column("supporting_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("proposed_risk", sa.Integer(), nullable=False),
        sa.Column("requires_approval", sa.Boolean(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
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
        op.f("ix_remediation_proposals_incident_id"),
        "remediation_proposals",
        ["incident_id"],
        unique=False,
    )

    # Create remediation_actions table
    op.create_table(
        "remediation_actions",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column(
            "proposal_id",
            GUID(),
            sa.ForeignKey("remediation_proposals.id"),
            nullable=False,
        ),
        sa.Column("incident_id", GUID(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("decision", sa.String(length=50), nullable=False),
        sa.Column("action_type", sa.String(length=50), nullable=False),
        sa.Column("policy_level", sa.Integer(), nullable=True),
        sa.Column("approval_required", sa.Boolean(), nullable=True),
        sa.Column("executor", sa.String(length=255), nullable=True),
        sa.Column("validated_parameters", sa.JSON(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("approved_by", sa.String(length=100), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
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
        op.f("ix_remediation_actions_proposal_id"),
        "remediation_actions",
        ["proposal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_remediation_actions_incident_id"),
        "remediation_actions",
        ["incident_id"],
        unique=False,
    )

    # Create remediation_results table
    op.create_table(
        "remediation_results",
        sa.Column("id", GUID(), primary_key=True, nullable=False),
        sa.Column(
            "action_id",
            GUID(),
            sa.ForeignKey("remediation_actions.id"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("before_state", sa.JSON(), nullable=True),
        sa.Column("after_state", sa.JSON(), nullable=True),
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
        op.f("ix_remediation_results_action_id"),
        "remediation_results",
        ["action_id"],
        unique=True,
    )


def downgrade() -> None:
    # Drop remediation_results table and index
    op.drop_index(op.f("ix_remediation_results_action_id"), table_name="remediation_results")
    op.drop_table("remediation_results")

    # Drop remediation_actions table and indexes
    op.drop_index(op.f("ix_remediation_actions_incident_id"), table_name="remediation_actions")
    op.drop_index(op.f("ix_remediation_actions_proposal_id"), table_name="remediation_actions")
    op.drop_table("remediation_actions")

    # Drop remediation_proposals table and index
    op.drop_index(
        op.f("ix_remediation_proposals_incident_id"),
        table_name="remediation_proposals",
    )
    op.drop_table("remediation_proposals")

    # Drop langgraph_thread_id column from incidents
    op.drop_index(op.f("ix_incidents_langgraph_thread_id"), table_name="incidents")
    op.drop_column("incidents", "langgraph_thread_id")
