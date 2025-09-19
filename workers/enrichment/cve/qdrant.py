"""Lightweight Qdrant HTTP client for advisory embeddings."""

from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

try:  # pragma: no cover - optional dependency for unit tests
    from requests import Session
except ImportError:  # pragma: no cover
    Session = object  # type: ignore[misc, assignment]

from .schemas import CVEAdvisory, CVEEnrichmentJob

LOG = logging.getLogger("medusa.workers.enrichment.cve.qdrant")


@dataclass
class QdrantConfig:
    """Configuration for connecting to the Qdrant HTTP API."""

    url: str
    collection: str
    api_key: Optional[str] = None
    timeout: float = 5.0


@dataclass
class QdrantPoint:
    """Payload describing a single point to upsert into Qdrant."""

    id: str
    vector: Sequence[float]
    payload: Mapping[str, Any]


class QdrantError(RuntimeError):
    """Raised when Qdrant rejects a request or is unavailable."""


def normalize_vector(vector: Sequence[float]) -> List[float]:
    """Return a unit-length vector or zeros when the magnitude is empty."""

    values = [float(component) for component in vector]
    if not values:
        return []
    magnitude = math.sqrt(sum(component * component for component in values))
    if magnitude == 0.0:
        return [0.0 for _ in values]
    return [component / magnitude for component in values]


def deterministic_embedding(text: str, *, dimensions: int = 64) -> List[float]:
    """Generate a deterministic pseudo-embedding for advisory content."""

    if dimensions <= 0:
        raise ValueError("dimensions must be positive")
    if not text.strip():
        return [0.0] * dimensions

    seed = hashlib.sha256(text.encode("utf-8")).digest()
    buffer = bytearray(seed)
    counter = 0
    required_bytes = dimensions * 4
    while len(buffer) < required_bytes:
        counter_bytes = counter.to_bytes(4, "big", signed=False)
        buffer.extend(hashlib.sha256(seed + counter_bytes).digest())
        counter += 1

    vector: List[float] = []
    for index in range(dimensions):
        chunk = buffer[index * 4 : (index + 1) * 4]
        integer = int.from_bytes(chunk, "big", signed=False)
        normalized = (integer / 0xFFFFFFFF) * 2 - 1
        vector.append(normalized)
    return vector


def build_advisory_points(
    job: CVEEnrichmentJob,
    advisories: Sequence[CVEAdvisory],
    *,
    dimensions: int = 64,
    embedding_version: int = 1,
) -> List[QdrantPoint]:
    """Create deterministic Qdrant points for the advisories in a job."""

    points: List[QdrantPoint] = []
    for index, advisory in enumerate(advisories):
        embedding_text = _compose_embedding_text(job, advisory)
        vector = deterministic_embedding(embedding_text, dimensions=dimensions)
        payload = _build_payload(job, advisory, embedding_version)
        points.append(
            QdrantPoint(
                id=f"{job.job_id}:{advisory.source}:{index}",
                vector=vector,
                payload=payload,
            )
        )
    return points


def _compose_embedding_text(job: CVEEnrichmentJob, advisory: CVEAdvisory) -> str:
    metadata_json = json.dumps(job.metadata, sort_keys=True, default=str)
    advisory_raw = json.dumps(advisory.raw, sort_keys=True, default=str)
    references = "\n".join(sorted(advisory.references))
    parts = [
        job.title,
        job.severity,
        job.finding_id,
        job.cve_id or "",
        metadata_json,
        advisory.identifier,
        advisory.summary or "",
        advisory.severity or "",
        str(advisory.cvss_score) if advisory.cvss_score is not None else "",
        references,
        advisory_raw,
    ]
    return "\n".join(part for part in parts if part)


def _isoformat(value) -> Optional[str]:  # pragma: no cover - exercised via build payload
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        if getattr(value, "tzinfo", None) is not None:
            return value.astimezone(value.tzinfo).isoformat()
        return value.isoformat()
    return str(value)


def _build_payload(
    job: CVEEnrichmentJob, advisory: CVEAdvisory, embedding_version: int
) -> Dict[str, Any]:
    metadata = {}
    if job.metadata:
        try:
            metadata = json.loads(json.dumps(job.metadata, sort_keys=True, default=str))
        except (TypeError, ValueError):
            metadata = {key: str(value) for key, value in job.metadata.items()}

    payload: Dict[str, Any] = {
        "job_id": job.job_id,
        "finding_id": job.finding_id,
        "scan_id": job.scan_id,
        "requested_by": job.requested_by,
        "requested_at": job.requested_at.isoformat(),
        "source": str(advisory.source),
        "advisory_identifier": advisory.identifier,
        "advisory_summary": advisory.summary,
        "advisory_severity": advisory.severity,
        "advisory_cvss": advisory.cvss_score,
        "published": _isoformat(advisory.published),
        "modified": _isoformat(advisory.modified),
        "references": advisory.references or None,
        "finding_title": job.title,
        "finding_severity": job.severity,
        "metadata": metadata or None,
        "embedding_version": embedding_version,
    }
    return {key: value for key, value in payload.items() if value is not None}


class QdrantClient:
    """Minimal HTTP client for the Qdrant upsert endpoint."""

    def __init__(
        self,
        config: QdrantConfig,
        *,
        session: Optional[Session] = None,
    ) -> None:
        if not config.url:
            raise ValueError("Qdrant URL must be provided")
        if not config.collection:
            raise ValueError("Qdrant collection must be provided")

        self._config = config
        if session is not None:
            self._session = session
            self._owns_session = False
        else:
            if Session is object:  # pragma: no cover - ensures dependency is installed
                raise RuntimeError("requests is required for Qdrant integration")
            self._session = Session()  # type: ignore[call-arg]
            self._owns_session = True

    def close(self) -> None:
        if self._owns_session and hasattr(self._session, "close"):
            self._session.close()

    def upsert(self, points: Sequence[QdrantPoint]) -> None:
        if not points:
            LOG.debug("No advisory vectors to upsert into Qdrant")
            return

        url = f"{self._config.url.rstrip('/')}/collections/{self._config.collection}/points"
        payload = {
            "points": [
                {
                    "id": point.id,
                    "vector": normalize_vector(point.vector),
                    "payload": json.loads(json.dumps(point.payload, sort_keys=True, default=str)),
                }
                for point in points
            ]
        }

        headers = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["api-key"] = self._config.api_key

        try:
            response = self._session.put(  # type: ignore[operator]
                url,
                json=payload,
                params={"wait": "true"},
                headers=headers,
                timeout=self._config.timeout,
            )
        except Exception as exc:  # pragma: no cover - raised when HTTP request fails
            raise QdrantError(f"Failed to upsert points: {exc}") from exc

        status_code = getattr(response, "status_code", 500)
        if status_code >= 400:
            message = getattr(response, "text", "")
            raise QdrantError(
                f"Qdrant returned status {status_code}: {message or 'no response body'}"
            )

        LOG.debug(
            "Upserted %s advisories into Qdrant",
            len(points),
            extra={"collection": self._config.collection},
        )


__all__ = [
    "QdrantClient",
    "QdrantConfig",
    "QdrantError",
    "QdrantPoint",
    "build_advisory_points",
    "deterministic_embedding",
    "normalize_vector",
]
