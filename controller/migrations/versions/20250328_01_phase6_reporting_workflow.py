"""Add finding workflow metadata, comments, and ticket tables"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250328_01"
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
            server_default="open",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("assigned_to", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "tags",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )

    op.create_table(
        "finding_comments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("author", sa.String(length=128), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "metadata_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("metadata_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_finding_comments_finding_id",
        "finding_comments",
        ["finding_id"],
    )

    op.create_table(
        "finding_tickets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("integration", sa.String(length=32), nullable=False),
        sa.Column("reference", sa.String(length=128), nullable=False),
        sa.Column("url", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column(
            "payload",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_finding_tickets_finding_id",
        "finding_tickets",
        ["finding_id"],
    )

    # Ensure existing rows receive normalized defaults once the server default is removed
    op.execute(sa.text("UPDATE findings SET status = 'open' WHERE status IS NULL"))
    op.execute(sa.text("UPDATE findings SET tags = '[]' WHERE tags IS NULL"))

    op.alter_column("findings", "status", server_default=None)
    op.alter_column("findings", "tags", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_finding_tickets_finding_id", table_name="finding_tickets")
    op.drop_table("finding_tickets")

    op.drop_index("ix_finding_comments_finding_id", table_name="finding_comments")
    op.drop_table("finding_comments")

    op.drop_column("findings", "tags")
    op.drop_column("findings", "assigned_to")
    op.drop_column("findings", "status")

