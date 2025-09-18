"""Verify Alembic migrations match the SQLAlchemy models."""
from __future__ import annotations

import os
import pathlib

from alembic import command
from alembic.config import Config
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from controller.db.models import Base

DEFAULT_CHECK_URL = "sqlite+pysqlite:///./migration_check.db"


def run_migrations(url: str) -> None:
    config = Config(str(pathlib.Path(__file__).resolve().parent.parent / "alembic.ini"))
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
