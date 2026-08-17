"""add change intelligence fields to incidents, incident_postmortems, and incident_memories

Revision ID: 007_add_change_intelligence_fields
Revises: 006_incident_memory_and_postmortems
Create Date: 2026-08-17 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "007_add_change_intelligence_fields"
down_revision: str | None = "006_incident_memory_and_postmortems"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add change fields to incidents table
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "recent_changes",
                sa.JSON(),
                nullable=False,
                server_default="[]",
            )
        )
        batch_op.add_column(
            sa.Column(
                "causal_changes",
                sa.JSON(),
                nullable=False,
                server_default="[]",
            )
        )

    # 2. Add change fields to incident_postmortems table
    with op.batch_alter_table("incident_postmortems", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "recent_changes",
                sa.JSON(),
                nullable=False,
                server_default="[]",
            )
        )
        batch_op.add_column(
            sa.Column(
                "causal_change_summary",
                sa.Text(),
                nullable=True,
            )
        )

    # 3. Add change fields to incident_memories table
    with op.batch_alter_table("incident_memories", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "causal_change_summary",
                sa.Text(),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "causal_change_type",
                sa.String(length=100),
                nullable=True,
            )
        )


def downgrade() -> None:
    # 1. Revert incident_memories columns
    with op.batch_alter_table("incident_memories", schema=None) as batch_op:
        batch_op.drop_column("causal_change_type")
        batch_op.drop_column("causal_change_summary")

    # 2. Revert incident_postmortems columns
    with op.batch_alter_table("incident_postmortems", schema=None) as batch_op:
        batch_op.drop_column("causal_change_summary")
        batch_op.drop_column("recent_changes")

    # 3. Revert incidents columns
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_column("causal_changes")
        batch_op.drop_column("recent_changes")
