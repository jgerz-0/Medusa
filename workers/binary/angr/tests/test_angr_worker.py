import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Mapping, Optional

import pytest

from workers.binary.angr.schemas import AngrArtifact, AngrJob
from workers.binary.angr.worker import (
    AngrAnalysisProcessor,
    CallbackClient,
    QueuedJob,
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
            }
        )
        return self.response


class FakeCallback(CallbackClient):
    def __init__(self) -> None:
        self.payloads: List[Mapping[str, object]] = []

    def post(self, url: str, payload: Mapping[str, object]) -> None:  # type: ignore[override]
        self.payloads.append({"url": url, "payload": payload})


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
