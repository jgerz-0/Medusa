"""Add finding validation tracking table."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20250405_01"
down_revision = "20250328_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_validations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("validator", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("outcome", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by", sa.String(length=128), nullable=True),
        sa.Column(
            "metadata_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("metadata_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "evidence",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    op.create_index(
        "ix_finding_validations_finding_id",
        "finding_validations",
        ["finding_id"],
    )
    op.create_index(
        "ix_finding_validations_scan_id",
        "finding_validations",
        ["scan_id"],
    )

    op.alter_column("finding_validations", "status", server_default=None)
    op.alter_column("finding_validations", "attempts", server_default=None)
    op.alter_column("finding_validations", "metadata_json", server_default=None)
    op.alter_column("finding_validations", "evidence", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_finding_validations_scan_id", table_name="finding_validations")
    op.drop_index("ix_finding_validations_finding_id", table_name="finding_validations")
    op.drop_table("finding_validations")
