"""add candidate_causal_changes column to incidents table

Revision ID: 008_add_candidate_causal_changes_column
Revises: 007_add_change_intelligence_fields
Create Date: 2026-08-17 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "008_add_candidate_causal_changes_column"
down_revision: str | None = "007_add_change_intelligence_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add candidate_causal_changes column to incidents table
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "candidate_causal_changes",
                sa.JSON(),
                nullable=False,
                server_default="[]",
            )
        )


def downgrade() -> None:
    # Revert candidate_causal_changes column from incidents table
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_column("candidate_causal_changes")
