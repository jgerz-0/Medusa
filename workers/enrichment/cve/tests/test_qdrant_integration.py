import json
from collections import deque
from datetime import datetime, timezone

import pytest

from workers.enrichment.cve import worker
from workers.enrichment.cve.qdrant import (
    QdrantClient,
    QdrantConfig,
    QdrantError,
    QdrantPoint,
    build_advisory_points,
    deterministic_embedding,
    normalize_vector,
)
from workers.enrichment.cve.schemas import (
    CVEAdvisory,
    CVEEnrichmentJob,
    CVEEnrichmentResult,
    CVESource,
)


class DummyResponse:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class DummySession:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text
        self.calls = []

    def put(self, url, json=None, params=None, headers=None, timeout=None):
        self.calls.append(
            {
                "url": url,
                "json": json,
                "params": params,
                "headers": headers,
                "timeout": timeout,
            }
        )
        return DummyResponse(status_code=self.status_code, text=self.text)


def test_deterministic_embedding_is_stable() -> None:
    text = "CVE-2024-0001 example"
    vec_one = deterministic_embedding(text, dimensions=8)
    vec_two = deterministic_embedding(text, dimensions=8)

    assert vec_one == vec_two
    assert len(vec_one) == 8


def test_normalize_vector_returns_unit_length() -> None:
    vector = normalize_vector([3.0, 4.0])
    magnitude = sum(component * component for component in vector) ** 0.5

    assert pytest.approx(1.0, rel=1e-6) == magnitude


def test_build_advisory_points_embeds_metadata() -> None:
    job = CVEEnrichmentJob(
        job_id="job-embedding",
        finding_id="finding-embedding",
        scan_id="scan-123",
        cve_id="CVE-2024-9000",
        title="Example finding",
        severity="high",
        metadata={"service": "ssh"},
        requested_by="svc-analyst",
        requested_at=datetime.now(timezone.utc),
    )
    advisory = CVEAdvisory(
        source=CVESource.NVD,
        identifier="CVE-2024-9000",
        summary="Deterministic summary",
        severity="CRITICAL",
        cvss_score=9.8,
        references=["https://example.com/advisory"],
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        raw={"id": "CVE-2024-9000"},
    )

    points = build_advisory_points(job, [advisory], dimensions=16)

    assert len(points) == 1
    point = points[0]
    assert point.id.startswith(job.job_id)
    assert point.payload["finding_id"] == job.finding_id
    assert point.payload["advisory_identifier"] == advisory.identifier
    assert len(point.vector) == 16


def test_qdrant_client_upsert_success() -> None:
    session = DummySession()
    client = QdrantClient(
        QdrantConfig(
            url="http://qdrant:6333",
            collection="medusa-test",
            api_key="secret",
            timeout=2.0,
        ),
        session=session,
    )
    point = QdrantPoint(id="point-1", vector=[1.0, 0.0, 0.0, 0.0], payload={"foo": "bar"})

    client.upsert([point])

    assert session.calls, "expected HTTP request to be recorded"
    call = session.calls[0]
    assert call["url"].endswith("/collections/medusa-test/points")
    assert call["headers"]["api-key"] == "secret"
    sent_vector = call["json"]["points"][0]["vector"]
    assert pytest.approx(1.0) == sum(component * component for component in sent_vector) ** 0.5


def test_qdrant_client_upsert_failure_raises() -> None:
    session = DummySession(status_code=500, text="boom")
    client = QdrantClient(
        QdrantConfig(url="http://qdrant:6333", collection="medusa-test"),
        session=session,
    )
    point = QdrantPoint(id="point-2", vector=[0.0, 1.0], payload={})

    with pytest.raises(QdrantError):
        client.upsert([point])


class FakeRedisConnection:
    def __init__(self, job_key: str, result_key: str, error_key: str) -> None:
        self.job_key = job_key
        self.result_key = result_key
        self.error_key = error_key
        self.queues = {
            job_key: deque(),
            result_key: deque(),
            error_key: deque(),
        }

    def preload(self, key: str, value: str) -> None:
        self.queues.setdefault(key, deque()).append(value)

    def blpop(self, key: str, timeout=None):
        queue = self.queues.setdefault(key, deque())
        if queue:
            return key, queue.popleft()
        return None

    def rpush(self, key: str, value: str) -> None:
        self.queues.setdefault(key, deque()).append(value)


def _make_worker_config(**overrides) -> worker.WorkerConfig:
    base = dict(
        redis_url="redis://test",
        queue_key="queues:jobs",
        result_queue_key="queues:results",
        error_queue_key="queues:errors",
        qdrant_url="http://qdrant:6333",
        qdrant_collection="medusa-advisories",
        qdrant_vector_size=8,
    )
    base.update(overrides)
    return worker.WorkerConfig(**base)


def test_process_queue_once_publishes_to_qdrant(monkeypatch):
    config = _make_worker_config()
    fake_conn = FakeRedisConnection(
        config.queue_key, config.result_queue_key, config.error_queue_key
    )
    job = worker.build_job_from_finding(
        finding_id="finding-qdrant-1",
        scan_id="scan-qdrant-1",
        title="Example",
        severity="medium",
        metadata={"scanner": "nuclei"},
        cve_id="CVE-2024-1234",
        requested_by="svc-analyst",
    )
    fake_conn.preload(config.queue_key, job.json())
    queue = worker.RedisJobQueue(config, connection=fake_conn)

    enrichment_result = CVEEnrichmentResult(
        job_id=job.job_id,
        finding_id=job.finding_id,
        advisories=[
            CVEAdvisory(
                source=CVESource.NVD,
                identifier="CVE-2024-1234",
                summary="Example advisory",
                severity="HIGH",
                cvss_score=8.2,
                references=["https://example.com"],
                raw={"source": "nvd"},
            )
        ],
        errors={},
    )
    monkeypatch.setattr(
        worker,
        "collect_advisories",
        lambda *_args, **_kwargs: enrichment_result,
    )

    captured_points: list[list[QdrantPoint]] = []

    class RecordingQdrant:
        def upsert(self, points):
            captured_points.append(points)

    processed = worker.process_queue_once(
        config,
        queue=queue,
        session=None,
        qdrant_client=RecordingQdrant(),
    )

    assert processed is True
    assert captured_points, "expected Qdrant upsert to be invoked"
    point = captured_points[0][0]
    assert point.payload["finding_id"] == job.finding_id

    result_payload = json.loads(fake_conn.queues[config.result_queue_key][0])
    assert result_payload["status"] == "completed"


def test_process_queue_once_logs_qdrant_error(monkeypatch, caplog):
    config = _make_worker_config()
    fake_conn = FakeRedisConnection(
        config.queue_key, config.result_queue_key, config.error_queue_key
    )
    job = worker.build_job_from_finding(
        finding_id="finding-qdrant-2",
        scan_id="scan-qdrant-2",
        title="Example",
        severity="medium",
        metadata={},
        cve_id="CVE-2024-9876",
        requested_by="svc-analyst",
    )
    fake_conn.preload(config.queue_key, job.json())
    queue = worker.RedisJobQueue(config, connection=fake_conn)

    enrichment_result = CVEEnrichmentResult(
        job_id=job.job_id,
        finding_id=job.finding_id,
        advisories=[
            CVEAdvisory(
                source=CVESource.CIRCL,
                identifier="CVE-2024-9876",
                summary="Example advisory",
                references=[],
                raw={"source": "circl"},
            )
        ],
        errors={},
    )
    monkeypatch.setattr(
        worker,
        "collect_advisories",
        lambda *_args, **_kwargs: enrichment_result,
    )

    class FailingQdrant:
        def upsert(self, points):
            raise RuntimeError("boom")

    with caplog.at_level("ERROR"):
        processed = worker.process_queue_once(
            config,
            queue=queue,
            session=None,
            qdrant_client=FailingQdrant(),
        )

    assert processed is True
    assert any(
        "Failed to upsert advisories into Qdrant" in record.message for record in caplog.records
    )
    result_payload = json.loads(fake_conn.queues[config.result_queue_key][0])
    assert result_payload["status"] == "completed"
    assert not fake_conn.queues[config.error_queue_key]
