"""Integration tests validating nuclei worker resilience when subprocesses crash."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from queue import Queue
from typing import Deque, List

import pytest

from workers.web.nuclei import worker


class InMemoryQueue:
    """Thread-safe in-memory stand-in for the Redis queue implementation."""

    def __init__(self, config: worker.WorkerConfig, *, jobs: List[str] | None = None) -> None:
        self.queue_key = config.queue_key
        self.dead_letter_key = config.dead_letter_key
        self.max_retries = config.max_retries
        self._jobs: Deque[str] = deque(jobs or [])
        self._dead_letter_entries: List[str] = []
        self._lock = threading.Lock()

    def fetch(self) -> worker.NucleiJob | None:
        with self._lock:
            if not self._jobs:
                return None
            payload = self._jobs.popleft()
        return worker.NucleiJob.from_json(payload)

    def retry(self, job: worker.NucleiJob, reason: str) -> None:
        next_attempt = job.attempts + 1
        if next_attempt > self.max_retries:
            self.dead_letter(job, reason)
            return
        requeued = job.with_attempt(next_attempt)
        with self._lock:
            self._jobs.append(requeued.to_json())

    def dead_letter(self, job: worker.NucleiJob, reason: str) -> None:
        payload = dict(job.raw)
        payload.update({"error": reason, "dead_lettered_at": int(time.time())})
        with self._lock:
            self._dead_letter_entries.append(json.dumps(payload))

    def snapshot_jobs(self) -> List[str]:
        with self._lock:
            return list(self._jobs)

    def snapshot_dead_letters(self) -> List[str]:
        with self._lock:
            return list(self._dead_letter_entries)


@pytest.fixture()
def base_job() -> worker.NucleiJob:
    """Return a minimal, controller-compliant nuclei job payload."""

    job = worker.NucleiJob(
        job_id="job-crash-test",
        target="https://target.example",
        templates=["http/test"],
        scan_id="scan-crash-test",
        callback_url="https://controller.internal/nuclei/callback",
        metadata={"scan_id": "scan-crash-test"},
    )
    job.raw.update({
        "job_id": job.job_id,
        "scan_id": job.scan_id,
        "target": job.target,
        "templates": job.templates,
        "callback_url": job.callback_url,
        "metadata": job.metadata,
        "attempts": job.attempts,
    })
    return job


def _run_attempt(
    config: worker.WorkerConfig,
    queue: InMemoryQueue,
    pid_queue: Queue[int],
) -> threading.Thread:
    """Spawn a worker attempt that crashes the nuclei subprocess."""

    def run_scan(job: worker.NucleiJob, _config: worker.WorkerConfig) -> worker.ScanResult:
        # Launch a long-lived helper process so the test can terminate it.
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        pid_queue.put(process.pid)
        start = time.time()
        exit_code = process.wait()
        duration = time.time() - start
        stdout = process.stdout.read() if process.stdout else ""
        stderr = process.stderr.read() if process.stderr else ""
        return worker.ScanResult(
            records=[],
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_seconds=duration,
        )

    def attempt() -> None:
        job = queue.fetch()
        if not job:
            return
        try:
            worker.process_job(job, config, queue, run_scan=run_scan, session=None, s3_client=None)
        except worker.RetryableJobError as exc:
            queue.retry(job, str(exc))
        except worker.FatalJobError as exc:
            queue.dead_letter(job, str(exc))

    thread = threading.Thread(target=attempt)
    thread.start()
    return thread


def _kill_subprocess(pid_queue: Queue[int]) -> None:
    pid = pid_queue.get(timeout=5)
    os.kill(pid, signal.SIGKILL)


def test_nuclei_worker_requeues_when_scan_process_is_killed(base_job: worker.NucleiJob) -> None:
    config = worker.WorkerConfig()
    config.max_retries = 3
    config.poll_timeout = 1

    queue = InMemoryQueue(config, jobs=[base_job.to_json()])
    pid_queue: Queue[int] = Queue()

    attempt_thread = _run_attempt(config, queue, pid_queue)
    _kill_subprocess(pid_queue)
    attempt_thread.join(timeout=10)
    assert not attempt_thread.is_alive(), "worker attempt thread failed to terminate"

    queued_jobs = queue.snapshot_jobs()
    assert len(queued_jobs) == 1
    payload = json.loads(queued_jobs[0])
    assert payload["attempts"] == 1, "job should be requeued with incremented attempts"
    assert queue.snapshot_dead_letters() == []


def test_nuclei_worker_dead_letters_after_exhausting_retries(base_job: worker.NucleiJob) -> None:
    config = worker.WorkerConfig()
    config.max_retries = 1
    config.poll_timeout = 1

    queue = InMemoryQueue(config, jobs=[base_job.to_json()])

    # First failure triggers a retry.
    first_pid_queue: Queue[int] = Queue()
    first_attempt = _run_attempt(config, queue, first_pid_queue)
    _kill_subprocess(first_pid_queue)
    first_attempt.join(timeout=10)
    assert not first_attempt.is_alive()
    queued_jobs = queue.snapshot_jobs()
    assert len(queued_jobs) == 1
    first_payload = json.loads(queued_jobs[0])
    assert first_payload["attempts"] == 1

    # Second failure should exceed max_retries and land in the dead-letter list.
    second_pid_queue: Queue[int] = Queue()
    second_attempt = _run_attempt(config, queue, second_pid_queue)
    _kill_subprocess(second_pid_queue)
    second_attempt.join(timeout=10)
    assert not second_attempt.is_alive()

    assert queue.snapshot_jobs() == []
    dead_entries = queue.snapshot_dead_letters()
    assert len(dead_entries) == 1
    dead_payload = json.loads(dead_entries[0])
    assert dead_payload["error"].startswith("nuclei exited with code"), dead_payload
    assert "dead_lettered_at" in dead_payload
