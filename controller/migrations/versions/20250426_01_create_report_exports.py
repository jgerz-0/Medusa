"""Create report exports table for persisted report artifacts."""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250426_01"
down_revision = "20250422_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_exports",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("content_type", sa.String(length=64), nullable=False),
        sa.Column("content_length", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_bucket", sa.String(length=128), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
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
        ),
    )
    op.create_index(
        "ix_report_exports_generated_at",
        "report_exports",
        ["generated_at"],
    )
    op.create_index(
        "ix_report_exports_requested_by",
        "report_exports",
        ["requested_by"],
    )
    op.create_index(
        "ix_report_exports_scan_id",
        "report_exports",
        ["scan_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_report_exports_scan_id", table_name="report_exports")
    op.drop_index("ix_report_exports_requested_by", table_name="report_exports")
    op.drop_index("ix_report_exports_generated_at", table_name="report_exports")
    op.drop_table("report_exports")
