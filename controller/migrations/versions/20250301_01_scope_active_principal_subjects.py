"""Scope principal subject uniqueness to active credentials"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20250301_01"
down_revision = "20250214_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("principal_credentials") as batch_op:
        batch_op.drop_constraint(
            "principal_credentials_subject_key", type_="unique"
        )

    op.create_index(
        "ux_principal_credentials_active_subject",
        "principal_credentials",
        ["subject"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
        sqlite_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ux_principal_credentials_active_subject",
        table_name="principal_credentials",
    )

    with op.batch_alter_table("principal_credentials") as batch_op:
        batch_op.create_unique_constraint(
            "principal_credentials_subject_key", ["subject"]
        )
