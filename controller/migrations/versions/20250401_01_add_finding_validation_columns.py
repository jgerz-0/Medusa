"""Add validation metadata columns to findings"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20250401_01"
down_revision = "20250320_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="pending_validation",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("validation_status", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "validation_metadata",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.execute(
        """
        UPDATE findings
        SET
            status = 'open',
            validation_status = 'passed',
            validated_at = COALESCE(validated_at, CURRENT_TIMESTAMP)
        """
    )


def downgrade() -> None:
    op.drop_column("findings", "validation_metadata")
    op.drop_column("findings", "validation_status")
    op.drop_column("findings", "validated_at")
    op.drop_column("findings", "status")
