"""Unit tests for the active recon execution pipeline."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from workers.recon.worker import (
    ActiveReconEngine,
    ReconExecution,
    ReconFeed,
    ReconJob,
    ReconTargetSpec,
    ReconTooling,
    WorkerConfig,
)


class _RunnerStub:
    """Deterministic subprocess runner used for unit tests."""

    def __init__(self) -> None:
        self.invocations: List[List[str]] = []

    def __call__(
        self,
        command: List[str],
        *,
        capture_output: bool = True,
        text: bool = True,
        check: bool = False,
        timeout: int | None = None,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.invocations.append(command)
        binary = command[0]
        if binary.endswith("subfinder"):
            payload = json.dumps({"host": "api.example.com"}) + "\n"
            return subprocess.CompletedProcess(command, 0, payload, "")
        if binary.endswith("amass"):
            return subprocess.CompletedProcess(command, 0, "vpn.example.com\n", "")
        if binary.endswith("httpx"):
            response: Dict[str, Any] = {
                "url": "https://api.example.com",
                "host": "api.example.com",
                "port": 443,
                "status-code": 200,
                "technologies": ["Go"],
                "webserver": "nginx",
                "tls": True,
                "ip": "203.0.113.10",
            }
            payload = json.dumps(response) + "\n"
            return subprocess.CompletedProcess(command, 0, payload, "")
        raise AssertionError(f"Unexpected command invocation: {command}")


def _active_job() -> ReconJob:
    feed = ReconFeed(type="csv", url="")
    execution = ReconExecution(
        mode="active",
        targets=[
            ReconTargetSpec(
                scope="example.com",
                asset_type="domain",
                seed_assets=["portal.example.com"],
                target_id="target-1",
                name="Example Corp",
            )
        ],
        tooling=ReconTooling(
            subfinder=True,
            amass=True,
            httpx=True,
            httpx_ports=[80, 443],
            httpx_probe_tls=True,
        ),
    )
    return ReconJob(
        job_id="job-123",
        source="controller",
        feed=feed,
        authorized_scopes=["example.com"],
        labels=["attack-surface"],
        callback_url="https://controller/recon",
        execution=execution,
    )


def test_active_engine_enumerates_hosts_and_services() -> None:
    runner = _RunnerStub()
    engine = ActiveReconEngine(WorkerConfig(), runner=runner)
    job = _active_job()
    now = datetime.now(tz=timezone.utc)

    assets = engine.enumerate(job, now)

    # Expect domain assets for the original scope and discovered hosts plus an HTTP service.
    normalized = {(asset.asset_type, asset.normalized_value) for asset in assets}
    assert ("domain", "example.com") in normalized
    assert ("domain", "api.example.com") in normalized
    assert ("domain", "vpn.example.com") in normalized
    assert any(item for item in normalized if item[0] == "url")

    # Ensure metadata records target provenance and tooling sources.
    domain_asset = next(asset for asset in assets if asset.normalized_value == "api.example.com")
    assert domain_asset.metadata["target_id"] == "target-1"
    assert sorted(domain_asset.metadata["sources"]) == ["subfinder", "target-scope"]

    url_asset = next(asset for asset in assets if asset.asset_type == "url")
    assert url_asset.metadata["service"]["status_code"] == 200
    assert url_asset.metadata["service"]["technologies"] == ["Go"]
    assert url_asset.metadata["port"] == 443
    assert url_asset.metadata["target_name"] == "Example Corp"

    # All tooling should have been invoked exactly once.
    binaries = {command[0] for command in runner.invocations}
    assert binaries == {"subfinder", "amass", "httpx"}


@pytest.mark.parametrize(
    "payload,expected_ports",
    [
        ({"httpx_ports": ["80", 443, "8443"]}, [80, 443, 8443]),
        ({"httpx_ports": ["bad", -1, 70000]}, [80, 443, 8080]),
    ],
)
def test_recon_tooling_port_normalization(payload: Dict[str, Any], expected_ports: List[int]) -> None:
    tooling = ReconTooling.from_json(payload)
    assert tooling.httpx_ports == expected_ports
