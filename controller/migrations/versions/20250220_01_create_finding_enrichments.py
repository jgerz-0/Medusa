"""Create finding enrichment table"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20250220_01"
down_revision = "20250214_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_enrichments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("job_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "advisories",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("advisories_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "errors",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("errors_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "provenance",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("provenance_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
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
        "ix_finding_enrichments_finding_id",
        "finding_enrichments",
        ["finding_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_finding_enrichments_finding_id", table_name="finding_enrichments")
    op.drop_table("finding_enrichments")
