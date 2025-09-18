"""Create principal credentials table"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20240405_01"
down_revision = "20240314_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "principal_credentials",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("subject", sa.String(length=255), nullable=False, unique=True),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=128), nullable=True),
        sa.Column("roles", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("principal_credentials")
