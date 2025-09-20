"""Seed the database with authorized targets for local testing."""

from __future__ import annotations

import logging
from typing import Iterable, List

from sqlalchemy.exc import SQLAlchemyError

from controller.db.models import Target
from controller.db.session import session_scope

logger = logging.getLogger(__name__)

SAMPLE_TARGETS = (
    {
        "name": "Medusa Demo Web",
        # Explicitly specify scheme to satisfy HTTP scope validation.
        "scope": "https://demo.medusa.internal",
        "is_authorized": True,
    },
    {
        "name": "Medusa API",
        # API endpoint is also accessed over HTTPS in local testing.
        "scope": "https://api.medusa.internal",
        "is_authorized": True,
    },
    {
        "name": "Medusa Staging Cluster",
        "scope": "10.10.0.0/24",
        "is_authorized": True,
    },
)


def seed_targets(targets: Iterable[dict]) -> None:
    """Insert authorized targets if they do not already exist."""

    targets_list: List[dict] = list(targets)
    with session_scope() as session:
        for target in targets_list:
            existing = (
                session.query(Target)
                .filter(Target.scope == target["scope"])
                .one_or_none()
            )
            if existing:
                logger.info("Target %s already present; skipping", target["scope"])
                continue
            session.add(Target(**target))
        logger.info("Seeded %d targets", len(targets_list))


def main() -> None:
    try:
        seed_targets(SAMPLE_TARGETS)
    except SQLAlchemyError as exc:
        logger.exception("Failed to seed targets: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
