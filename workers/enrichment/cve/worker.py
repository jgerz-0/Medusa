"""Entry point for the CVE enrichment worker.

The implementation intentionally focuses on deterministic data retrieval so
future enrichment logic can build on a trustworthy base.  The worker currently
accepts a single job payload (via --job-file or STDIN), fetches advisories
from the configured sources, and emits a normalized JSON document.  Queue
integration will be layered on top in a future iteration.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional

try:  # pragma: no cover - requests optional in unit tests
    from requests import Session
except ImportError:  # pragma: no cover
    Session = object  # type: ignore[misc, assignment]

from .schemas import CVEAdvisory, CVEEnrichmentJob, CVEEnrichmentResult, CVESource
from .sources import AdvisorySourceError, fetch_circl_advisory, fetch_nvd_advisory

LOG = logging.getLogger("medusa.workers.enrichment.cve")


@dataclass
class WorkerConfig:
    """Runtime configuration derived from environment variables."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv(
            "CVE_ENRICHMENT_QUEUE_KEY", "queues:enrichment:cve"
        )
    )
    result_queue_key: str = field(
        default_factory=lambda: os.getenv(
            "CVE_ENRICHMENT_RESULT_QUEUE_KEY", "queues:enrichment:cve:results"
        )
    )
    http_timeout: int = field(
        default_factory=lambda: int(os.getenv("CVE_ENRICHMENT_HTTP_TIMEOUT", "30"))
    )
    user_agent: Optional[str] = field(
        default_factory=lambda: os.getenv("CVE_ENRICHMENT_USER_AGENT")
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded worker configuration", extra={"config": config})
        return config


SOURCE_FETCHERS: Mapping[CVESource, Callable[..., Dict[str, object]]] = {
    CVESource.NVD: fetch_nvd_advisory,
    CVESource.CIRCL: fetch_circl_advisory,
}


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE enrichment worker")
    parser.add_argument(
        "--job-file",
        dest="job_file",
        help="Path to a JSON file containing the enrichment job payload",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        default=os.getenv("LOG_LEVEL", "INFO"),
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def load_job_from_stream(stream) -> CVEEnrichmentJob:
    try:
        payload = stream.read()
    except Exception as exc:  # pragma: no cover - defensive
        raise SystemExit(f"failed to read job payload: {exc}") from exc
    if not payload:
        raise SystemExit("job payload is empty")
    try:
        return CVEEnrichmentJob.parse_raw(payload)
    except ValueError as exc:
        raise SystemExit(f"invalid job payload: {exc}") from exc


def load_job(path: Optional[str]) -> CVEEnrichmentJob:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return load_job_from_stream(handle)
    return load_job_from_stream(sys.stdin)


def collect_advisories(
    job: CVEEnrichmentJob,
    *,
    config: WorkerConfig,
    session: Optional[Session] = None,
) -> CVEEnrichmentResult:
    advisories: list[CVEAdvisory] = []
    errors: MutableMapping[CVESource, str] = {}
    if not job.cve_id:
        for source in job.sources:
            errors[source] = "job missing cve_id"
        return CVEEnrichmentResult(
            job_id=job.job_id,
            finding_id=job.finding_id,
            advisories=advisories,
            errors=dict(errors),
        )

    for source in job.sources:
        fetcher = SOURCE_FETCHERS.get(source)
        if fetcher is None:
            errors[source] = "source not implemented"
            continue
        try:
            payload = fetcher(
                job.cve_id,
                session=session,
                user_agent=config.user_agent,
                timeout=config.http_timeout,
            )
            advisories.append(CVEAdvisory.parse_obj(payload))
        except AdvisorySourceError as exc:
            errors[source] = str(exc)
        except Exception as exc:  # pragma: no cover - ensures deterministic errors
            errors[source] = f"unexpected error: {exc}"
    return CVEEnrichmentResult(
        job_id=job.job_id,
        finding_id=job.finding_id,
        advisories=advisories,
        errors=dict(errors),
    )


def build_job_from_finding(
    *,
    finding_id: str,
    scan_id: Optional[str],
    title: str,
    severity: str,
    metadata: Optional[Dict[str, object]] = None,
    cve_id: Optional[str] = None,
    sources: Optional[Iterable[str]] = None,
    requested_by: str,
) -> CVEEnrichmentJob:
    payload: Dict[str, Any] = {
        "job_id": str(uuid.uuid4()),
        "finding_id": finding_id,
        "scan_id": scan_id,
        "cve_id": cve_id,
        "title": title,
        "severity": severity,
        "metadata": metadata or {},
        "requested_by": requested_by,
        "requested_at": datetime.now(tz=timezone.utc),
    }
    if sources is not None:
        payload["sources"] = list(sources)
    return CVEEnrichmentJob(**payload)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = WorkerConfig.load()

    job = load_job(args.job_file)
    LOG.info("Processing enrichment job", extra={"job_id": job.job_id, "finding_id": job.finding_id})

    session: Optional[Session] = None
    if Session is not object:  # pragma: no branch - ensures optional dependency support
        session = Session()  # type: ignore[call-arg]

    result = collect_advisories(job, config=config, session=session)
    if session and hasattr(session, "close"):
        session.close()
    serialized = result.json(by_alias=True, exclude_none=True)
    print(serialized)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
