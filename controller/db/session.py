"""Database session utilities for the controller service."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

DEFAULT_DATABASE_URL = "postgresql+psycopg://medusa:medusa@localhost:5432/medusa"


def get_database_url() -> str:
    """Return the configured database URL, falling back to the local dev default."""

    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def create_db_engine(url: Optional[str] = None, **kwargs: object) -> Engine:
    """Create a SQLAlchemy engine bound to the configured database."""

    database_url = url or get_database_url()
    return create_engine(database_url, future=True, **kwargs)


ENGINE: Engine = create_db_engine()
SessionLocal = sessionmaker(bind=ENGINE, expire_on_commit=False, class_=Session)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
