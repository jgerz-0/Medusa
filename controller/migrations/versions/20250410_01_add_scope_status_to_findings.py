"""Add scope status classification to findings."""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250410_01"
down_revision = "20250404_01"
branch_labels = None
depends_on = None


SCOPE_STATUS_COLUMN = "scope_status"
DEFAULT_SCOPE_STATUS = "unknown"


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            SCOPE_STATUS_COLUMN,
            sa.String(length=32),
            nullable=False,
            server_default=DEFAULT_SCOPE_STATUS,
        ),
    )
    op.execute(
        sa.text(
            "UPDATE findings SET scope_status = :default WHERE scope_status IS NULL"
        ),
        {"default": DEFAULT_SCOPE_STATUS},
    )
    op.alter_column("findings", SCOPE_STATUS_COLUMN, server_default=None)


def downgrade() -> None:
    op.drop_column("findings", SCOPE_STATUS_COLUMN)
