"""Create table for binary static analysis findings"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20250312_01"
down_revision = "20250301_01"
branch_labels = None
depends_on = ("20250220_01",)


def upgrade() -> None:
    op.create_table(
        "binary_static_analysis_findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "sample_id",
            sa.String(length=36),
            sa.ForeignKey("binary_samples.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "metadata_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "evidence",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_bucket", sa.String(length=128), nullable=True),
        sa.Column("artifact_key", sa.String(length=512), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
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
        "ix_binary_static_analysis_findings_sample_id",
        "binary_static_analysis_findings",
        ["sample_id"],
    )
    op.create_index(
        "ix_binary_static_analysis_findings_scan_id",
        "binary_static_analysis_findings",
        ["scan_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_binary_static_analysis_findings_scan_id",
        table_name="binary_static_analysis_findings",
    )
    op.drop_index(
        "ix_binary_static_analysis_findings_sample_id",
        table_name="binary_static_analysis_findings",
    )
    op.drop_table("binary_static_analysis_findings")
