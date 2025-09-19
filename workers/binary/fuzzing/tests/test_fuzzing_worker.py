import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from workers.binary.fuzzing.schemas import FuzzingJob
from workers.binary.fuzzing.worker import (
    CallbackClient,
    FuzzingArtifactStorage,
    FuzzingProcessor,
    QueuedJob,
    WorkerConfig,
)
from workers.binary.static_analysis.schemas import AnalysisArtifact


class FakeStorage(FuzzingArtifactStorage):
    def __init__(self) -> None:
        self.saved: List[Dict[str, object]] = []

    def persist(
        self, job: FuzzingJob, tool: str, payload: Mapping[str, object]
    ) -> AnalysisArtifact:
        artifact = {
            "tool": tool,
            "bucket": "analysis",
            "key": f"fuzzing/{tool}.json",
            "payload": dict(payload),
        }
        self.saved.append(artifact)
        return AnalysisArtifact(tool=tool, bucket="analysis", key=f"fuzzing/{tool}.json")

    def fetch_original(self, bucket: str, key: str) -> bytes:
        return b"binary"


class FakeRunner:
    def __init__(self, responses: Dict[str, subprocess.CompletedProcess[str]]):
        self.responses = responses
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
                "environment": dict(environment or {}),
            }
        )
        return self.responses[image]


class FakeCallback(CallbackClient):
    def __init__(self) -> None:
        self.payloads: List[Mapping[str, object]] = []

    def post(self, url: str, payload: Mapping[str, object]) -> None:
        self.payloads.append({"url": url, "payload": payload})


def _completed_process(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["fake"], returncode=0, stdout=stdout, stderr="")


def test_fuzzing_processor_smoke() -> None:
    crashes_stdout = json.dumps(
        {
            "crashes": [
                {
                    "id": "c1",
                    "severity": "high",
                    "description": "Segmentation fault",
                    "evidence": {"input": "AAAA"},
                }
            ],
            "duration_seconds": 42,
        }
    )
    responses = {
        "docker.io/medusa/afl:latest": _completed_process(crashes_stdout),
        "docker.io/medusa/libfuzzer:latest": _completed_process(crashes_stdout),
    }

    runner = FakeRunner(responses)
    storage = FakeStorage()
    callback = FakeCallback()

    config = WorkerConfig()
    config.enable_afl = True
    config.enable_libfuzzer = True
    config.artifact_bucket = "analysis"
    config.artifact_prefix = "fuzzing/"
    config.container_flags = tuple()
    config.afl_command = ("/opt/medusa/run_afl",)
    config.libfuzzer_command = ("/opt/medusa/run_libfuzzer",)

    processor = FuzzingProcessor(
        config,
        runner=runner,  # type: ignore[arg-type]
        storage=storage,  # type: ignore[arg-type]
        callback=callback,  # type: ignore[arg-type]
    )

    job = FuzzingJob(
        job_id="job-1",
        scan_id="scan-1",
        sample_id="sample-1",
        target_id="target-1",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/fuzzing/callback",
        submitted_at=datetime.now(tz=timezone.utc),
    )
    queued_job = QueuedJob(
        job=job, attempts=0, raw_payload=json.dumps(job.model_dump(mode="json"))
    )

    processor.process(queued_job)

    assert len(runner.calls) == 2, "both fuzzers should run"
    assert len(callback.payloads) == 1
    payload = callback.payloads[0]["payload"]
    assert payload["status"] == "completed"
    assert len(payload["findings"]) == 2
    assert {artifact["tool"] for artifact in storage.saved} == {"afl", "libfuzzer"}

    for finding in payload["findings"]:
        assert finding["artifact_bucket"] == "analysis"
        assert finding["artifact_key"].startswith("fuzzing/")

