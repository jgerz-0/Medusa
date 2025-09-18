"""Verify Alembic migrations match the SQLAlchemy models."""

from __future__ import annotations

import os
import pathlib
import sys

from alembic import command
from alembic.config import Config
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_CHECK_URL = "sqlite+pysqlite:///./migration_check.db"

# Prevent eager engine creation from trying to reach a developer's Postgres
# instance when the drift check runs outside Docker.
os.environ.setdefault("DATABASE_URL", os.getenv("DATABASE_URL", DEFAULT_CHECK_URL))

from controller.db.models import Base


def run_migrations(url: str) -> None:
    config_path = pathlib.Path(__file__).resolve().parent.parent
    config = Config(str(config_path / "alembic.ini"))
    config.set_main_option("script_location", str(config_path / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")


def main() -> None:
    database_url = os.getenv("DATABASE_URL", DEFAULT_CHECK_URL)
    if database_url == DEFAULT_CHECK_URL:
        db_path = pathlib.Path("migration_check.db")
        if db_path.exists():
            db_path.unlink()
    run_migrations(database_url)

    engine = create_engine(database_url, future=True)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            diffs = compare_metadata(context, Base.metadata)
            if diffs:
                for diff in diffs:
                    print(f"Schema drift detected: {diff}")
                raise SystemExit(1)
    finally:
        engine.dispose()
        if database_url == DEFAULT_CHECK_URL:
            db_path = pathlib.Path("migration_check.db")
            if db_path.exists():
                db_path.unlink()


if __name__ == "__main__":
    main()
