"""Create recon_discoveries table for pending recon assets.

Revision ID: 20250412_01
Revises: 20250410_01
Create Date: 2025-04-12 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250412_01"
down_revision = "20250410_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recon_discoveries",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("raw_value", sa.String(length=1024), nullable=True),
        sa.Column("matched_scope", sa.String(length=512), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="new"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_target_id", sa.String(length=36), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_unique_constraint(
        "ux_recon_discovery_asset",
        "recon_discoveries",
        ["asset_type", "value"],
    )
    op.execute(
        "UPDATE recon_discoveries SET status = 'new' WHERE status IS NULL"
    )
    op.alter_column("recon_discoveries", "metadata", server_default=None)
    op.alter_column("recon_discoveries", "status", server_default=None)
    op.alter_column("recon_discoveries", "occurrences", server_default=None)


def downgrade() -> None:
    op.drop_constraint("ux_recon_discovery_asset", "recon_discoveries", type_="unique")
    op.drop_table("recon_discoveries")

