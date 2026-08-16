"""add classification and iteration_count to incidents table

Revision ID: 003_add_investigation_metadata
Revises: 002_add_fingerprint_service
Create Date: 2026-08-16 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003_add_investigation_metadata"
down_revision: str | None = "002_add_fingerprint_service"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("classification", sa.JSON(), nullable=True))
    op.add_column(
        "incidents",
        sa.Column("iteration_count", sa.Integer(), nullable=True, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("incidents", "iteration_count")
    op.drop_column("incidents", "classification")
