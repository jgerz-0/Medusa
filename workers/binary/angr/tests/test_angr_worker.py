from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional

import pytest

from workers.binary.angr.schemas import AngrArtifact, AngrJob
from workers.binary.angr.worker import (
    AngrAnalysisProcessor,
    ArtifactStorage,
    CallbackClient,
    QueuedJob,
    RedisJobQueue,
    Worker,
    WorkerConfig,
)
from workers.binary.static_analysis.runtime import RuntimeConfig


class FakeStorage:
    def __init__(self, *, prefix: str = "") -> None:
        self.saved: List[AngrArtifact] = []
        self.payloads: List[Mapping[str, object]] = []
        self.prefix = prefix

    def persist(self, job: AngrJob, name: str, payload: Mapping[str, object]):
        normalized_prefix = self.prefix.rstrip("/") + "/" if self.prefix else ""
        key = f"{normalized_prefix}{job.sample_id}/{name}.json"
        artifact = AngrArtifact(tool=name, bucket="analysis", key=key)
        self.saved.append(artifact)
        self.payloads.append(dict(payload))
        return artifact

    def fetch_original(self, bucket: str, key: str) -> bytes:
        return b"binary"


class FakeRunner:
    def __init__(self, response: subprocess.CompletedProcess[str]):
        self.response = response
        self.calls: List[Dict[str, object]] = []

    def run(
        self,
        image: str,
        command: List[str],
        *,
        mounts: Mapping[Path, str],
        extra_flags: Optional[List[str]] = None,
        environment: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
    ):
        self.calls.append(
            {
                "image": image,
                "command": list(command),
                "mounts": {str(k): v for k, v in mounts.items()},
                "environment": dict(environment or {}),
                "extra_flags": list(extra_flags or []),
            }
        )
        return self.response


class FakeCallback(CallbackClient):
    def __init__(self) -> None:
        self.payloads: List[Mapping[str, object]] = []

    def post(self, url: str, payload: Mapping[str, object]) -> None:  # type: ignore[override]
        self.payloads.append({"url": url, "payload": payload})


class RecordingObjectStorageClient:
    def __init__(self) -> None:
        self.put_calls: List[Dict[str, object]] = []

    def put_json(self, bucket: str, key: str, payload: Dict[str, object]) -> None:
        self.put_calls.append(
            {"bucket": bucket, "key": key, "payload": dict(payload)}
        )

    def fetch(self, bucket: str, key: str) -> bytes:  # pragma: no cover - not used in tests
        return b""


class DummyQueue:
    def __init__(self) -> None:
        self.requeued: List[Dict[str, object]] = []
        self.dead_lettered: List[Dict[str, object]] = []

    def fetch(self):  # pragma: no cover - interface shim
        return None

    def requeue(self, job: QueuedJob, *, reason: str, error: Optional[str]) -> None:
        self.requeued.append({"job": job, "reason": reason, "error": error})

    def dead_letter(self, job: QueuedJob, *, reason: str, error: Optional[str]) -> None:
        self.dead_lettered.append({"job": job, "reason": reason, "error": error})


class DummyProcessor:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls: List[QueuedJob] = []

    def process(self, job: QueuedJob) -> None:
        self.calls.append(job)
        if self.should_fail:
            raise RuntimeError("boom")


class DummyRedis:
    def __init__(self) -> None:
        self.pushed: List[Dict[str, str]] = []

    def blpop(self, *args, **kwargs):  # pragma: no cover - queue fetch not exercised here
        return None

    def rpush(self, key: str, payload: str) -> None:
        self.pushed.append({"key": key, "payload": payload})


def _completed_process(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["angr"], returncode=returncode, stdout=stdout, stderr="")


def test_runtime_rejects_unapproved_flag() -> None:
    config = RuntimeConfig()
    with pytest.raises(ValueError):
        config.validate_flags(["--privileged"])


def test_angr_processor_emits_normalized_callback() -> None:
    executed_at = datetime.now(tz=timezone.utc)
    harness_stdout = json.dumps(
        {
            "status": "completed",
            "metadata": {"paths": 3},
            "findings": [
                {
                    "tool": "angr",
                    "severity": "high",
                    "title": "Reachable strcpy",
                    "description": "User controlled path to strcpy",
                    "metadata": {"sink": "strcpy"},
                    "evidence": {"input": "AAAA"},
                    "executed_at": executed_at.isoformat(),
                    "artifact": "path_constraints",
                }
            ],
            "artifacts": [
                {
                    "name": "path_constraints",
                    "payload": {"path": ["0x401000", "0x401100"]},
                }
            ],
        }
    )

    config = WorkerConfig()
    config.analysis_bucket = "analysis"
    config.analysis_prefix = "analysis/symbolic/"
    config.container_flags = ("--cpus=1", "--memory=512m")

    runner = FakeRunner(_completed_process(harness_stdout))
    storage = FakeStorage(prefix=config.analysis_prefix)
    callback = FakeCallback()

    processor = AngrAnalysisProcessor(
        config,
        runner=runner,
        storage=storage,  # type: ignore[arg-type]
        callback=callback,  # type: ignore[arg-type]
    )

    job = AngrJob(
        job_id="job-angr-1",
        scan_id="scan-1",
        sample_id="sample-1",
        target_id="target-1",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/symbolic-execution/callback",
        submitted_at=datetime.now(tz=timezone.utc),
        metadata={"analysis_depth": 128},
    )
    queued_job = QueuedJob(job=job, attempts=0, raw_payload=json.dumps(job.model_dump(mode="json")))

    processor.process(queued_job)

    assert runner.calls, "container runtime should be invoked"
    call = runner.calls[0]
    assert call["environment"]["ANGR_ANALYSIS_DEPTH"] == "128"
    assert call["environment"]["ANGR_INPUT_PATH"].endswith("sample.bin")
    assert call["extra_flags"] == list(config.container_flags)

    assert len(storage.saved) == 1
    artifact_record = storage.saved[0]
    assert isinstance(artifact_record, AngrArtifact)
    assert artifact_record.tool == "path_constraints"

    assert len(callback.payloads) == 1
    payload = callback.payloads[0]["payload"]
    assert payload["status"] == "completed"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["artifacts"][0]["key"].startswith("analysis/symbolic/")
    assert payload["metadata"]["analysis_depth"] == 128
    assert payload["metadata"]["paths"] == 3


def test_angr_processor_marks_failures() -> None:
    runner = FakeRunner(_completed_process("{}", returncode=1))
    storage = FakeStorage()
    callback = FakeCallback()

    config = WorkerConfig()
    processor = AngrAnalysisProcessor(
        config,
        runner=runner,
        storage=storage,  # type: ignore[arg-type]
        callback=callback,  # type: ignore[arg-type]
    )
    job = AngrJob(
        job_id="job-angr-2",
        scan_id="scan-2",
        sample_id="sample-2",
        target_id="target-2",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/symbolic-execution/callback",
    )
    queued_job = QueuedJob(job=job, attempts=0, raw_payload=json.dumps(job.model_dump(mode="json")))

    processor.process(queued_job)

    assert callback.payloads, "callback should be emitted even on failure"
    payload = callback.payloads[0]["payload"]
    assert payload["status"] == "failed"
    assert payload["error"]


def test_artifact_storage_uses_configured_bucket_and_prefix() -> None:
    client = RecordingObjectStorageClient()
    storage = ArtifactStorage(
        client,  # type: ignore[arg-type]
        default_bucket="analysis-bucket",
        prefix="analysis/symbolic/",
    )
    job = AngrJob(
        job_id="job-angr-3",
        scan_id="scan-3",
        sample_id="sample-3",
        target_id="target-3",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/symbolic-execution/callback",
    )

    artifact = storage.persist(job, "paths", {"paths": 4})

    assert artifact.bucket == "analysis-bucket"
    assert artifact.key.startswith("analysis/symbolic/sample-3/paths-")
    assert client.put_calls
    put_record = client.put_calls[0]
    assert put_record["bucket"] == "analysis-bucket"
    assert put_record["payload"]["paths"] == 4


def test_artifact_storage_requires_bucket() -> None:
    client = RecordingObjectStorageClient()
    storage = ArtifactStorage(
        client,  # type: ignore[arg-type]
        default_bucket=None,
        prefix="analysis/symbolic/",
    )
    job = AngrJob(
        job_id="job-angr-4",
        scan_id="scan-4",
        sample_id="sample-4",
        target_id="target-4",
        object_bucket="",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/symbolic-execution/callback",
    )

    with pytest.raises(RuntimeError):
        storage.persist(job, "paths", {"paths": 1})


def test_worker_requeues_until_max_attempts() -> None:
    config = WorkerConfig()
    queue = DummyQueue()
    processor = DummyProcessor(should_fail=True)
    storage = FakeStorage()
    runner = FakeRunner(_completed_process("{}"))
    callback = FakeCallback()
    worker = Worker(
        config,
        runner=runner,  # type: ignore[arg-type]
        queue=queue,  # type: ignore[arg-type]
        storage=storage,  # type: ignore[arg-type]
        callback=callback,  # type: ignore[arg-type]
        processor=processor,  # type: ignore[arg-type]
    )
    job = AngrJob(
        job_id="job-angr-5",
        scan_id="scan-5",
        sample_id="sample-5",
        target_id="target-5",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/symbolic-execution/callback",
    )
    raw_payload = job.model_dump(mode="json")
    raw_payload["attempts"] = 0
    queued = QueuedJob(job=job, attempts=0, raw_payload=json.dumps(raw_payload))

    worker._handle_job(queued)

    assert processor.calls == [queued]
    assert queue.requeued
    assert not queue.dead_lettered
    retry_record = queue.requeued[0]
    assert retry_record["reason"] == "retry_pending"
    assert "boom" in str(retry_record["error"])


def test_worker_dead_letters_after_max_attempts() -> None:
    config = WorkerConfig()
    queue = DummyQueue()
    processor = DummyProcessor(should_fail=True)
    storage = FakeStorage()
    runner = FakeRunner(_completed_process("{}"))
    callback = FakeCallback()
    worker = Worker(
        config,
        runner=runner,  # type: ignore[arg-type]
        queue=queue,  # type: ignore[arg-type]
        storage=storage,  # type: ignore[arg-type]
        callback=callback,  # type: ignore[arg-type]
        processor=processor,  # type: ignore[arg-type]
    )
    job = AngrJob(
        job_id="job-angr-6",
        scan_id="scan-6",
        sample_id="sample-6",
        target_id="target-6",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/symbolic-execution/callback",
    )
    raw_payload = job.model_dump(mode="json")
    raw_payload["attempts"] = config.max_attempts - 1
    queued = QueuedJob(
        job=job,
        attempts=config.max_attempts - 1,
        raw_payload=json.dumps(raw_payload),
    )

    worker._handle_job(queued)

    assert queue.dead_lettered
    dead_record = queue.dead_lettered[0]
    assert dead_record["reason"] == "max_attempts_exceeded"
    assert "boom" in str(dead_record["error"])


def test_redis_queue_requeue_increments_attempts() -> None:
    config = WorkerConfig()
    redis_client = DummyRedis()
    queue = RedisJobQueue(config, connection=redis_client)  # type: ignore[arg-type]
    payload = {
        "job_id": "job-angr-7",
        "scan_id": "scan-7",
        "sample_id": "sample-7",
        "target_id": "target-7",
        "object_bucket": "binary-uploads",
        "object_key": "uploads/sample.bin",
        "file_name": "sample.bin",
        "callback_url": "https://controller/internal/binary/symbolic-execution/callback",
        "attempts": 1,
    }
    job = AngrJob.model_validate(payload)
    queued = QueuedJob(job=job, attempts=1, raw_payload=json.dumps(payload))

    queue.requeue(queued, reason="retry_pending", error="transient error")

    assert redis_client.pushed
    entry = redis_client.pushed[0]
    document = json.loads(entry["payload"])
    assert document["attempts"] == 2
    assert document["last_error"] == "transient error"
    assert document["last_failure_reason"] == "retry_pending"
    assert document["retry_history"][-1]["attempt"] == 2
