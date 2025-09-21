"""Add recon run and observation tables."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20250418_01"
down_revision = "20250415_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recon_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
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
            nullable=False,
        ),
        sa.Column("job_id", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="feed"),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="completed",
        ),
        sa.Column(
            "retrieved_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "authorized_scopes",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("tooling", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("targets", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.UniqueConstraint("job_id", name="ux_recon_run_job"),
    )

    op.create_table(
        "recon_observations",
        sa.Column("id", sa.String(length=36), primary_key=True),
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
        sa.Column(
            "run_id",
            sa.String(length=36),
            sa.ForeignKey("recon_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.String(length=36),
            sa.ForeignKey("targets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("normalized_value", sa.String(length=1024), nullable=False),
        sa.Column("raw_value", sa.String(length=1024), nullable=True),
        sa.Column("matched_scope", sa.String(length=512), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column(
            "occurrences",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column(
            "metadata",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "run_id",
            "asset_type",
            "normalized_value",
            "port",
            name="ux_recon_observation_asset",
        ),
    )

    op.alter_column("recon_runs", "mode", server_default=None)
    op.alter_column("recon_runs", "status", server_default=None)
    op.alter_column("recon_runs", "authorized_scopes", server_default=None)
    op.alter_column("recon_runs", "tooling", server_default=None)
    op.alter_column("recon_runs", "targets", server_default=None)
    op.alter_column("recon_runs", "metadata", server_default=None)

    op.alter_column("recon_observations", "occurrences", server_default=None)
    op.alter_column("recon_observations", "metadata", server_default=None)


def downgrade() -> None:
    op.drop_table("recon_observations")
    op.drop_table("recon_runs")
