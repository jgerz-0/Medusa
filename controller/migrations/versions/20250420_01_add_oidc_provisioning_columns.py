"""Add expiration and source metadata to principal credentials"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20250420_01"
down_revision = "20250415_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "principal_credentials",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "principal_credentials",
        sa.Column(
            "source",
            sa.String(length=64),
            nullable=False,
            server_default="manual",
        ),
    )
    op.execute("UPDATE principal_credentials SET source = 'manual' WHERE source IS NULL")
    op.alter_column(
        "principal_credentials",
        "source",
        server_default=None,
        existing_type=sa.String(length=64),
    )


def downgrade() -> None:
    op.drop_column("principal_credentials", "source")
    op.drop_column("principal_credentials", "expires_at")
