"""Backfill canonical hashes for legacy comment, validation, enrichment, and ticket rows."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250422_01"
down_revision = "20250420_01"
branch_labels = None
depends_on = None


def _canonicalize_for_hash(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        canonical: dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda item: str(item)):
            canonical[str(key)] = _canonicalize_for_hash(value[key])
        return canonical
    if isinstance(value, (list, tuple)):
        return [_canonicalize_for_hash(item) for item in value]
    if isinstance(value, (set, frozenset)):
        canonical_items = [_canonicalize_for_hash(item) for item in value]
        return sorted(
            canonical_items,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
        )
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return str(value)


def _hash_json_payload(payload: Any) -> str:
    canonical = _canonicalize_for_hash(payload)
    serialized = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    metadata = sa.MetaData()

    finding_comments = sa.Table("finding_comments", metadata, autoload_with=bind)
    finding_validations = sa.Table("finding_validations", metadata, autoload_with=bind)
    finding_enrichments = sa.Table("finding_enrichments", metadata, autoload_with=bind)
    finding_tickets = sa.Table("finding_tickets", metadata, autoload_with=bind)

    comments = bind.execute(
        sa.select(
            finding_comments.c.id,
            finding_comments.c.metadata_json,
        )
    ).fetchall()
    for row in comments:
        metadata_payload = row.metadata_json or {}
        bind.execute(
            finding_comments.update()
            .where(finding_comments.c.id == row.id)
            .values(metadata_hash=_hash_json_payload(metadata_payload))
        )

    validations = bind.execute(
        sa.select(
            finding_validations.c.id,
            finding_validations.c.metadata_json,
            finding_validations.c.evidence,
        )
    ).fetchall()
    for row in validations:
        metadata_payload = row.metadata_json or {}
        evidence_payload = row.evidence or {}
        bind.execute(
            finding_validations.update()
            .where(finding_validations.c.id == row.id)
            .values(
                metadata_hash=_hash_json_payload(metadata_payload),
                evidence_hash=_hash_json_payload(evidence_payload),
            )
        )

    enrichments = bind.execute(
        sa.select(
            finding_enrichments.c.id,
            finding_enrichments.c.job_id,
            finding_enrichments.c.finding_id,
            finding_enrichments.c.generated_at,
            finding_enrichments.c.advisories,
            finding_enrichments.c.errors,
            finding_enrichments.c.provenance,
        )
    ).fetchall()
    for row in enrichments:
        advisories_payload = row.advisories or []
        errors_payload = row.errors or {}
        provenance_payload = row.provenance or {}
        payload_material = {
            "job_id": row.job_id,
            "finding_id": row.finding_id,
            "advisories": advisories_payload,
            "errors": errors_payload,
            "generated_at": row.generated_at.isoformat()
            if row.generated_at is not None
            else None,
        }
        bind.execute(
            finding_enrichments.update()
            .where(finding_enrichments.c.id == row.id)
            .values(
                advisories_hash=_hash_json_payload(advisories_payload),
                errors_hash=_hash_json_payload(errors_payload),
                provenance_hash=_hash_json_payload(provenance_payload),
                payload_hash=_hash_json_payload(payload_material),
            )
        )

    tickets = bind.execute(
        sa.select(
            finding_tickets.c.id,
            finding_tickets.c.payload,
        )
    ).fetchall()
    for row in tickets:
        payload = row.payload or {}
        bind.execute(
            finding_tickets.update()
            .where(finding_tickets.c.id == row.id)
            .values(payload_hash=_hash_json_payload(payload))
        )


def downgrade() -> None:
    # Data migrations are not easily reversible without historical payloads.
    pass
