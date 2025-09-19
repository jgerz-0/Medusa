import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional

import pytest

from workers.binary.static_analysis.runtime import RuntimeConfig
from workers.binary.static_analysis.schemas import AnalysisArtifact, StaticAnalysisJob
from workers.binary.static_analysis.worker import (
    CallbackClient,
    QueuedJob,
    StaticAnalysisProcessor,
    WorkerConfig,
)


class FakeStorage:
    def __init__(self) -> None:
        self.saved: List[Dict[str, object]] = []

    def persist(self, job: StaticAnalysisJob, tool: str, payload: Mapping[str, object]):
        artifact = {
            "tool": tool,
            "bucket": "analysis",
            "key": f"reports/{tool}.json",
            "payload": dict(payload),
        }
        self.saved.append(artifact)
        return AnalysisArtifact(
            tool=tool, bucket="analysis", key=f"reports/{tool}.json"
        )

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
                "mounts": {str(k): v for k, v in mounts.items()},
            }
        )
        return self.responses[image]


class FakeCallback(CallbackClient):
    def __init__(self) -> None:
        self.payloads: List[Mapping[str, object]] = []

    def post(self, url: str, payload: Mapping[str, object]) -> None:
        self.payloads.append({"url": url, "payload": payload})


def _completed_process(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["fake"], returncode=0, stdout=stdout, stderr=""
    )


def test_runtime_rejects_unapproved_flag() -> None:
    config = RuntimeConfig()
    with pytest.raises(ValueError):
        config.validate_flags(["--privileged"])


def test_runtime_accepts_equals_style_flag() -> None:
    config = RuntimeConfig()
    validated = config.validate_flags(["--cpus=2"])
    assert validated == ["--cpus", "2"]


def test_static_analysis_processor_smoke() -> None:
    checksec_stdout = json.dumps({"checksec": {"nx": "no", "pie": "yes"}})
    bandit_stdout = json.dumps(
        {
            "results": [
                {
                    "issue_severity": "MEDIUM",
                    "issue_text": "Use of eval",
                    "test_id": "B307",
                    "filename": "app.py",
                    "line_number": 10,
                    "code": "eval('x')",
                    "more_info": "https://bandit",
                }
            ]
        }
    )

    responses = {
        "docker.io/medusa/checksec:latest": _completed_process(checksec_stdout),
        "docker.io/medusa/bandit:latest": _completed_process(bandit_stdout),
    }
    runner = FakeRunner(responses)
    storage = FakeStorage()
    callback = FakeCallback()

    config = WorkerConfig()
    config.enable_checksec = True
    config.enable_bandit = True
    config.analysis_bucket = "analysis"
    config.analysis_prefix = "reports/"

    processor = StaticAnalysisProcessor(
        config,
        runner=runner,
        storage=storage,  # type: ignore[arg-type]
        callback=callback,  # type: ignore[arg-type]
    )

    job = StaticAnalysisJob(
        job_id="job-1",
        scan_id="scan-1",
        sample_id="sample-1",
        target_id="target-1",
        object_bucket="binary-uploads",
        object_key="uploads/sample.bin",
        file_name="sample.bin",
        callback_url="https://controller/internal/binary/static-analysis/callback",
        submitted_at=datetime.now(tz=timezone.utc),
    )
    queued_job = QueuedJob(
        job=job, attempts=0, raw_payload=json.dumps(job.model_dump(mode="json"))
    )

    processor.process(queued_job)

    assert runner.calls, "container runtime should be invoked"
    assert len(callback.payloads) == 1
    payload = callback.payloads[0]["payload"]
    assert payload["status"] == "completed"
    assert len(payload["findings"]) == 2
    artifact_paths = {artifact["key"] for artifact in storage.saved}
    assert "reports/checksec.json" in artifact_paths
    assert "reports/bandit.json" in artifact_paths

    for finding in payload["findings"]:
        assert finding["artifact_bucket"] == "analysis"
        assert finding["artifact_key"].startswith("reports/")
