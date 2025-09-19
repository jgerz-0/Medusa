import json
from collections import deque
from datetime import datetime, timezone

import pytest

from workers.enrichment.cve import worker
from workers.enrichment.cve.schemas import (
    CVEAdvisory,
    CVEEnrichmentJob,
    CVEEnrichmentResult,
    CVESource,
)
from workers.enrichment.cve.sources import (
    AdvisorySourceError,
    fetch_circl_advisory,
    fetch_nvd_advisory,
)


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class DummySession:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get(self, url, params=None, timeout=None, headers=None):
        self.calls.append(
            {"url": url, "params": params, "timeout": timeout, "headers": headers}
        )
        return DummyResponse(self.payload)


def test_fetch_nvd_advisory_normalizes_payload():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "descriptions": [{"value": "Example vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {"baseScore": 9.8},
                                "baseSeverity": "CRITICAL",
                            }
                        ]
                    },
                    "references": {
                        "referenceData": [
                            {"url": "https://example.com/advisory"},
                            {"url": "https://mirror.example.com/advisory"},
                        ]
                    },
                    "published": "2023-01-01T00:00:00Z",
                    "lastModified": "2023-01-02T00:00:00Z",
                }
            }
        ]
    }
    session = DummySession(payload)
    advisory = fetch_nvd_advisory(
        "CVE-2023-0001", session=session, user_agent="test-agent"
    )

    assert advisory["identifier"] == "CVE-2023-0001"
    assert advisory["severity"] == "CRITICAL"
    assert advisory["cvss_score"] == 9.8
    assert advisory["references"] == [
        "https://example.com/advisory",
        "https://mirror.example.com/advisory",
    ]
    assert advisory["published"].tzinfo == timezone.utc
    assert session.calls[0]["headers"]["User-Agent"] == "test-agent"


def test_fetch_circl_advisory_handles_summary_variants():
    payload = {
        "id": "CVE-2023-0002",
        "summary": "CIRCL summary",
        "cvss": {"score": 7.5, "severity": "HIGH"},
        "Published": "2023-05-01T12:30:00",
        "last-modified": "2023-05-02T01:00:00Z",
        "references": ["https://circl.example.org/advisory"],
    }
    session = DummySession(payload)
    advisory = fetch_circl_advisory("CVE-2023-0002", session=session)

    assert advisory["identifier"] == "CVE-2023-0002"
    assert advisory["severity"] == "HIGH"
    assert advisory["cvss_score"] == 7.5
    assert advisory["references"] == ["https://circl.example.org/advisory"]
    assert advisory["published"].tzinfo == timezone.utc


def test_collect_advisories_handles_missing_cve_id():
    job = CVEEnrichmentJob(
        job_id="job-1",
        finding_id="finding-1",
        scan_id="scan-1",
        cve_id=None,
        title="Example",
        severity="high",
        metadata={},
        requested_by="svc-analyst",
        requested_at=datetime.now(timezone.utc),
    )
    config = worker.WorkerConfig()
    result = worker.collect_advisories(job, config=config, session=None)

    assert result.advisories == []
    assert result.errors[CVESource.NVD] == "job missing cve_id"
    assert result.errors[CVESource.CIRCL] == "job missing cve_id"


def test_collect_advisories_aggregates_sources(monkeypatch):
    job = CVEEnrichmentJob(
        job_id="job-2",
        finding_id="finding-2",
        scan_id="scan-2",
        cve_id="CVE-2023-9999",
        title="Example",
        severity="critical",
        metadata={},
        sources=[CVESource.NVD],
        requested_by="svc-analyst",
        requested_at=datetime.now(timezone.utc),
    )
    config = worker.WorkerConfig()

    def fake_fetcher(cve_id, **kwargs):
        return {
            "source": "nvd",
            "identifier": cve_id,
            "summary": "Example",
            "severity": "CRITICAL",
            "cvss_score": 9.1,
            "references": ["https://example.com"],
            "published": datetime.now(timezone.utc),
            "modified": datetime.now(timezone.utc),
            "raw": {"id": cve_id},
        }

    monkeypatch.setitem(worker.SOURCE_FETCHERS, CVESource.NVD, fake_fetcher)
    result = worker.collect_advisories(job, config=config, session=None)

    assert len(result.advisories) == 1
    assert result.advisories[0].identifier == "CVE-2023-9999"
    assert result.errors == {}


def test_collect_advisories_records_source_error(monkeypatch):
    job = CVEEnrichmentJob(
        job_id="job-3",
        finding_id="finding-3",
        scan_id="scan-3",
        cve_id="CVE-2023-1000",
        title="Example",
        severity="medium",
        metadata={},
        sources=[CVESource.CIRCL],
        requested_by="svc-analyst",
        requested_at=datetime.now(timezone.utc),
    )
    config = worker.WorkerConfig()

    def failing_fetcher(*args, **kwargs):
        raise AdvisorySourceError("timeout")

    monkeypatch.setitem(worker.SOURCE_FETCHERS, CVESource.CIRCL, failing_fetcher)
    result = worker.collect_advisories(job, config=config, session=None)

    assert result.advisories == []
    assert result.errors[CVESource.CIRCL] == "timeout"


def test_main_serializes_result(tmp_path, monkeypatch, capsys):
    job = worker.build_job_from_finding(
        finding_id="finding-4",
        scan_id="scan-4",
        title="Example",
        severity="medium",
        metadata={"cpe": ["cpe:/a:example"]},
        cve_id="CVE-2023-2000",
        sources=[CVESource.NVD.value],
        requested_by="svc-admin",
    )
    job_file = tmp_path / "job.json"
    job_file.write_text(job.json(), encoding="utf-8")

    fake_result = CVEEnrichmentResult(
        job_id=job.job_id,
        finding_id=job.finding_id,
        advisories=[
            CVEAdvisory(
                source=CVESource.NVD,
                identifier="CVE-2023-2000",
                summary="Example",
                severity="HIGH",
                cvss_score=8.5,
                references=["https://example.com"],
                published=datetime.now(timezone.utc),
                modified=datetime.now(timezone.utc),
                raw={"example": True},
            )
        ],
        errors={},
        generated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        worker.WorkerConfig, "load", classmethod(lambda cls: worker.WorkerConfig())
    )
    monkeypatch.setattr(
        worker, "collect_advisories", lambda job, config, session=None: fake_result
    )
    monkeypatch.setattr(worker, "Session", object)

    exit_code = worker.main(["--job-file", str(job_file), "--log-level", "DEBUG"])
    assert exit_code == 0

    output = capsys.readouterr().out.strip()
    payload = json.loads(output)
    assert payload["job_id"] == job.job_id
    assert payload["advisories"][0]["identifier"] == "CVE-2023-2000"


class FakeRedisConnection:
    def __init__(self, job_key: str, result_key: str, error_key: str):
        self.job_key = job_key
        self.result_key = result_key
        self.error_key = error_key
        self.queues = {
            job_key: deque(),
            result_key: deque(),
            error_key: deque(),
        }
        self.push_log: list[tuple[str, str]] = []

    def preload(self, key: str, value: str) -> None:
        self.queues.setdefault(key, deque()).append(value)

    def blpop(self, key: str, timeout=None):
        queue = self.queues.setdefault(key, deque())
        if queue:
            return key, queue.popleft()
        return None

    def rpush(self, key: str, value: str) -> None:
        self.push_log.append((key, value))
        self.queues.setdefault(key, deque()).append(value)


def _make_worker_config(**overrides):
    base = dict(
        redis_url="redis://test",
        queue_key="queues:jobs",
        result_queue_key="queues:results",
        error_queue_key="queues:errors",
    )
    base.update(overrides)
    return worker.WorkerConfig(**base)


def _dequeue_json(fake_conn: FakeRedisConnection, key: str):
    queue = fake_conn.queues[key]
    assert queue, f"expected payload on {key}"
    return json.loads(queue[0])


def _raise_runtime_error(message: str):
    def _raiser(*_args, **_kwargs):
        raise RuntimeError(message)

    return _raiser


def test_process_queue_once_publishes_results(monkeypatch):
    config = _make_worker_config()
    fake_conn = FakeRedisConnection(
        config.queue_key, config.result_queue_key, config.error_queue_key
    )
    job = worker.build_job_from_finding(
        finding_id="finding-queue-1",
        scan_id="scan-queue-1",
        title="Example",
        severity="medium",
        metadata={},
        cve_id="CVE-2023-3000",
        requested_by="svc-analyst",
    )
    fake_conn.preload(config.queue_key, job.json())
    queue = worker.RedisJobQueue(config, connection=fake_conn)

    fake_result = worker.CVEEnrichmentResult(
        job_id=job.job_id,
        finding_id=job.finding_id,
        advisories=[],
        errors={},
    )
    monkeypatch.setattr(
        worker,
        "collect_advisories",
        lambda queued_job, config, session=None: fake_result,
    )

    processed = worker.process_queue_once(config, queue=queue, session=None)
    assert processed is True

    result_payload = _dequeue_json(fake_conn, config.result_queue_key)
    assert result_payload["status"] == "completed"
    assert result_payload["job"]["job_id"] == job.job_id
    assert result_payload["result"]["job_id"] == job.job_id
    assert not fake_conn.queues[config.queue_key]


def test_process_queue_once_requeues_on_error(monkeypatch):
    config = _make_worker_config(max_attempts=3, retry_backoff_seconds=0.0)
    fake_conn = FakeRedisConnection(
        config.queue_key, config.result_queue_key, config.error_queue_key
    )
    job = worker.build_job_from_finding(
        finding_id="finding-queue-2",
        scan_id="scan-queue-2",
        title="Example",
        severity="medium",
        metadata={},
        cve_id="CVE-2023-3001",
        requested_by="svc-analyst",
    )
    fake_conn.preload(config.queue_key, job.json())
    queue = worker.RedisJobQueue(config, connection=fake_conn)

    monkeypatch.setattr(worker, "collect_advisories", _raise_runtime_error("boom"))
    monkeypatch.setattr(worker.time, "sleep", lambda *_args, **_kwargs: None)

    processed = worker.process_queue_once(config, queue=queue, session=None)
    assert processed is True

    retry_payload = _dequeue_json(fake_conn, config.queue_key)
    assert retry_payload["attempts"] == 1
    assert retry_payload["last_error"]["message"] == "boom"

    status_payload = _dequeue_json(fake_conn, config.result_queue_key)
    assert status_payload["status"] == "retrying"
    assert status_payload["error"]["message"] == "boom"
    assert not fake_conn.queues[config.error_queue_key]


def test_process_queue_once_dead_letters(monkeypatch):
    config = _make_worker_config(max_attempts=1)
    fake_conn = FakeRedisConnection(
        config.queue_key, config.result_queue_key, config.error_queue_key
    )
    job = worker.build_job_from_finding(
        finding_id="finding-queue-3",
        scan_id="scan-queue-3",
        title="Example",
        severity="medium",
        metadata={},
        cve_id="CVE-2023-3002",
        requested_by="svc-analyst",
    )
    fake_conn.preload(config.queue_key, job.json())
    queue = worker.RedisJobQueue(config, connection=fake_conn)

    monkeypatch.setattr(worker, "collect_advisories", _raise_runtime_error("fail"))

    processed = worker.process_queue_once(config, queue=queue, session=None)
    assert processed is True

    assert not fake_conn.queues[config.queue_key]
    result_payload = _dequeue_json(fake_conn, config.result_queue_key)
    assert result_payload["status"] == "failed"
    assert result_payload["error"]["message"] == "fail"

    error_payload = _dequeue_json(fake_conn, config.error_queue_key)
    assert error_payload["status"] == "failed"
    assert error_payload["error"]["message"] == "fail"
