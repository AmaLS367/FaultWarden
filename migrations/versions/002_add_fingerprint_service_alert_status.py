"""add fingerprint, service, and alert_status to incidents table

Revision ID: 002_add_fingerprint_service
Revises: 001_initial
Create Date: 2026-08-16 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_add_fingerprint_service"
down_revision: str | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.add_column("incidents", sa.Column("service", sa.String(length=100), nullable=True))
    op.add_column(
        "incidents",
        sa.Column("alert_status", sa.String(length=30), nullable=True, server_default="firing"),
    )

    op.create_index(op.f("ix_incidents_fingerprint"), "incidents", ["fingerprint"], unique=False)
    op.create_index(op.f("ix_incidents_service"), "incidents", ["service"], unique=False)
    op.create_index(op.f("ix_incidents_alert_status"), "incidents", ["alert_status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_incidents_alert_status"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_service"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_fingerprint"), table_name="incidents")

    op.drop_column("incidents", "alert_status")
    op.drop_column("incidents", "service")
    op.drop_column("incidents", "fingerprint")
