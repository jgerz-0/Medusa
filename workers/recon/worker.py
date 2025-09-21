"""Recon worker that ingests external inventory feeds and normalises assets."""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

try:  # pragma: no cover - optional dependency at runtime
    import redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

try:  # pragma: no cover - optional dependency at runtime
    import requests
    from requests import Response, Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

    class Session:  # type: ignore
        def request(self, *args: Any, **kwargs: Any) -> Response:  # pragma: no cover
            raise RuntimeError("requests is required to execute recon jobs")

    class Response:  # type: ignore
        ...

    class RequestException(Exception):
        ...


LOG = logging.getLogger("medusa.workers.recon")
CALLBACK_TOKEN_HEADER = "X-Callback-Token"
SUPPORTED_ASSET_TYPES = {"domain", "ipv4", "ipv6", "url"}


@dataclass
class WorkerConfig:
    """Runtime configuration controlling queue connectivity and HTTP timeouts."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv("RECON_QUEUE_KEY", "queues:recon:jobs")
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv("RECON_DEAD_LETTER_KEY", "queues:recon:dead")
    )
    poll_timeout: int = field(
        default_factory=lambda: int(os.getenv("RECON_POLL_TIMEOUT", "5"))
    )
    max_retries: int = field(
        default_factory=lambda: int(os.getenv("RECON_MAX_RETRIES", "3"))
    )
    http_timeout: int = field(
        default_factory=lambda: int(os.getenv("RECON_HTTP_TIMEOUT", "10"))
    )
    callback_token: Optional[str] = field(
        default_factory=lambda: os.getenv("RECON_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_RECON_CALLBACK_TOKEN")
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded recon worker config", extra={"config": config})
        return config


@dataclass
class ReconFeed:
    type: str
    url: str
    delimiter: str = ","
    asset_column: str = "asset"
    asset_type_column: Optional[str] = None
    encoding: str = "utf-8"
    method: str = "GET"
    items_path: List[str] = field(default_factory=list)
    asset_field: str = "asset"
    type_field: Optional[str] = None


@dataclass
class ReconJob:
    job_id: str
    source: str
    feed: ReconFeed
    authorized_scopes: List[str]
    labels: List[str]
    callback_url: str
    requested_by: Optional[str] = None
    queued_at: Optional[str] = None

    @classmethod
    def from_json(cls, payload: str) -> "ReconJob":
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid job payload: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Job payload must be a JSON object")

        job_id = str(data.get("job_id") or "").strip()
        if not job_id:
            raise ValueError("Job payload missing 'job_id'")

        source = str(data.get("source") or "").strip()
        if not source:
            raise ValueError("Job payload missing 'source'")

        callback_url = str(data.get("callback_url") or "").strip()
        if not callback_url:
            raise ValueError("Job payload missing 'callback_url'")

        feed_payload = data.get("feed")
        if not isinstance(feed_payload, dict):
            raise ValueError("Job payload missing 'feed' configuration")

        feed_type = str(feed_payload.get("type") or "").strip().lower()
        if feed_type not in {"csv", "api"}:
            raise ValueError("Feed type must be 'csv' or 'api'")

        feed_url = str(feed_payload.get("url") or "").strip()
        if not feed_url:
            raise ValueError("Feed configuration missing 'url'")

        feed = ReconFeed(
            type=feed_type,
            url=feed_url,
            delimiter=str(feed_payload.get("delimiter") or ","),
            asset_column=str(feed_payload.get("asset_column") or "asset"),
            asset_type_column=feed_payload.get("asset_type_column"),
            encoding=str(feed_payload.get("encoding") or "utf-8"),
            method=str(feed_payload.get("method") or "GET").upper(),
            items_path=[str(item) for item in feed_payload.get("items_path", [])],
            asset_field=str(feed_payload.get("asset_field") or "asset"),
            type_field=feed_payload.get("type_field"),
        )

        scopes = [
            str(scope).strip()
            for scope in data.get("authorized_scopes", [])
            if isinstance(scope, str) and scope.strip()
        ]
        if not scopes:
            raise ValueError("At least one authorized scope is required")

        labels = [
            str(label).strip().lower()
            for label in data.get("labels", [])
            if isinstance(label, str) and label.strip()
        ]

        requested_by = str(data.get("requested_by") or "").strip() or None
        queued_at = str(data.get("queued_at") or "").strip() or None

        return cls(
            job_id=job_id,
            source=source,
            feed=feed,
            authorized_scopes=scopes,
            labels=labels,
            callback_url=callback_url,
            requested_by=requested_by,
            queued_at=queued_at,
        )


@dataclass
class ReconAsset:
    asset_type: str
    normalized_value: str
    raw_value: str
    matched_scope: Optional[str]
    metadata: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    occurrences: int = 1

    def to_payload(self) -> Dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "normalized_value": self.normalized_value,
            "raw_value": self.raw_value,
            "matched_scope": self.matched_scope,
            "metadata": self.metadata,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "occurrences": max(1, self.occurrences),
        }


def _coerce_timestamp(value: Optional[datetime]) -> datetime:
    if value is None:
        return datetime.now(tz=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def normalize_asset(value: str, asset_type: Optional[str] = None) -> Tuple[str, str]:
    """Return a canonical (type, value) tuple for the provided asset string."""

    candidate = (value or "").strip()
    if not candidate:
        raise ValueError("Asset value cannot be empty")

    inferred_type = (asset_type or "").strip().lower()
    if inferred_type and inferred_type not in SUPPORTED_ASSET_TYPES:
        raise ValueError(f"Unsupported asset type: {asset_type}")

    if not inferred_type:
        if "://" in candidate:
            inferred_type = "url"
        else:
            try:
                ip_candidate = ip_address(candidate)
            except ValueError:
                inferred_type = "domain"
            else:
                inferred_type = "ipv6" if ip_candidate.version == 6 else "ipv4"

    if inferred_type in {"ipv4", "ipv6"}:
        ip_value = ip_address(candidate)
        normalized = str(ip_value)
        return inferred_type, normalized

    if inferred_type == "domain":
        normalized = candidate.lower().rstrip(".")
        if not normalized:
            raise ValueError("Domain asset must not be empty")
        return "domain", normalized

    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("URL assets must include a scheme and network location")

    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if host is None:
        raise ValueError("URL asset missing hostname")
    host_normalized = host.lower()
    if parsed.port:
        netloc = f"{host_normalized}:{parsed.port}"
    else:
        netloc = host_normalized
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    path = path.lower()
    normalized_url = f"{scheme}://{netloc}{path}"
    return "url", normalized_url


def _asset_matches_scope(asset_type: str, value: str, scope: str) -> bool:
    scope_candidate = scope.strip()
    if not scope_candidate:
        return False
    if asset_type in {"ipv4", "ipv6"}:
        try:
            ip_value = ip_address(value)
        except ValueError:
            return False
        try:
            network = ip_network(scope_candidate, strict=False)
        except ValueError:
            try:
                ip_candidate = ip_address(scope_candidate)
            except ValueError:
                return False
            return ip_value == ip_candidate
        return ip_value in network
    if asset_type == "url":
        parsed = urlparse(value)
        host = parsed.hostname
        if host is None:
            return False
        try:
            ip_value = ip_address(host)
        except ValueError:
            return _asset_matches_scope("domain", host.lower(), scope_candidate)
        return _asset_matches_scope(
            "ipv6" if ip_value.version == 6 else "ipv4", str(ip_value), scope_candidate
        )
    normalized_value = value.lower().rstrip(".")
    normalized_scope = scope_candidate.lower().rstrip(".")
    if normalized_scope == normalized_value:
        return True
    return normalized_value.endswith(f".{normalized_scope}")


def _match_authorized_scope(
    asset_type: str, value: str, scopes: Iterable[str]
) -> Optional[str]:
    for scope in scopes:
        if _asset_matches_scope(asset_type, value, scope):
            return scope
    return None


class ReconWorker:
    """Redis-backed recon worker that enriches the controller with discovered assets."""

    def __init__(
        self,
        config: WorkerConfig,
        *,
        redis_client: Optional["redis.Redis"] = None,
        http_session: Optional[Session] = None,
    ) -> None:
        if requests is None:  # pragma: no cover - runtime guard
            raise RuntimeError("requests package is required to run the recon worker")
        if redis is None and redis_client is None:  # pragma: no cover - runtime guard
            raise RuntimeError("redis package is required to run the recon worker")

        self._config = config
        self._redis = redis_client
        self._http = http_session or requests.Session()

    @property
    def redis(self):  # type: ignore[override]
        if self._redis is None:
            self._redis = redis.Redis.from_url(  # type: ignore[attr-defined]
                self._config.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    def run_forever(self) -> None:  # pragma: no cover - integration behaviour
        LOG.info(
            "Starting recon worker loop",
            extra={"queue_key": self._config.queue_key},
        )
        while True:
            job_payload = self._dequeue()
            if job_payload is None:
                continue
            try:
                job = ReconJob.from_json(job_payload)
            except Exception:
                LOG.exception("Failed to parse recon job payload")
                self.redis.rpush(self._config.dead_letter_key, job_payload)
                continue
            try:
                self.process_job(job)
            except Exception:
                LOG.exception("Recon job failed", extra={"job_id": job.job_id})
                self.redis.rpush(self._config.dead_letter_key, job_payload)
            time.sleep(0)

    def _dequeue(self) -> Optional[str]:
        result = self.redis.blpop(self._config.queue_key, timeout=self._config.poll_timeout)
        if result is None:
            return None
        _, payload = result
        return payload

    def process_job(self, job: ReconJob) -> None:
        assets = self.collect_assets(job)
        if not assets:
            LOG.info(
                "Recon job produced no authorized assets",
                extra={"job_id": job.job_id, "source": job.source},
            )
            return

        payload = {
            "job_id": job.job_id,
            "source": job.source,
            "retrieved_at": datetime.now(tz=timezone.utc).isoformat(),
            "assets": [asset.to_payload() for asset in assets],
        }
        headers = {"Content-Type": "application/json"}
        if self._config.callback_token:
            headers[CALLBACK_TOKEN_HEADER] = self._config.callback_token

        response = self._http.post(
            job.callback_url,
            data=json.dumps(payload),
            headers=headers,
            timeout=self._config.http_timeout,
        )
        if response.status_code >= 300:
            LOG.warning(
                "Controller rejected recon payload",
                extra={"status": response.status_code, "body": response.text[:200]},
            )

    def collect_assets(self, job: ReconJob) -> List[ReconAsset]:
        now = datetime.now(tz=timezone.utc)
        entries: List[ReconAsset] = []
        if job.feed.type == "csv":
            rows = self._load_csv(job.feed)
            entries.extend(self._extract_from_rows(rows, job, now))
        else:
            items = self._load_api(job.feed)
            entries.extend(self._extract_from_items(items, job, now))

        aggregated: Dict[Tuple[str, str], ReconAsset] = {}
        for asset in entries:
            matched_scope = _match_authorized_scope(
                asset.asset_type, asset.normalized_value, job.authorized_scopes
            )
            if not matched_scope:
                continue
            key = (asset.asset_type, asset.normalized_value)
            if key not in aggregated:
                metadata = dict(asset.metadata)
                if job.labels:
                    metadata.setdefault("labels", list(job.labels))
                aggregated[key] = ReconAsset(
                    asset_type=asset.asset_type,
                    normalized_value=asset.normalized_value,
                    raw_value=asset.raw_value,
                    matched_scope=matched_scope,
                    metadata=metadata,
                    first_seen=asset.first_seen,
                    last_seen=asset.last_seen,
                    occurrences=max(1, asset.occurrences),
                )
            else:
                record = aggregated[key]
                record.occurrences += max(1, asset.occurrences)
                record.last_seen = max(record.last_seen, asset.last_seen)
                if not record.raw_value:
                    record.raw_value = asset.raw_value
                if record.metadata != asset.metadata and asset.metadata:
                    record.metadata.update(asset.metadata)
                if not record.matched_scope:
                    record.matched_scope = matched_scope
        return list(aggregated.values())

    def _load_csv(self, feed: ReconFeed) -> List[Dict[str, Any]]:
        content = self._retrieve_text(feed.url, feed.encoding)
        reader = csv.DictReader(content.splitlines(), delimiter=feed.delimiter)
        return [dict(row) for row in reader]

    def _load_api(self, feed: ReconFeed) -> List[Any]:
        data = self._retrieve_json(feed.url, feed.method)
        value: Any = data
        for path_component in feed.items_path:
            if isinstance(value, dict):
                value = value.get(path_component)
            else:
                raise ValueError("items_path traversal failed; expected object")
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
        raise ValueError("API feed did not return an iterable payload")

    def _extract_from_rows(
        self, rows: Iterable[Dict[str, Any]], job: ReconJob, now: datetime
    ) -> List[ReconAsset]:
        assets: List[ReconAsset] = []
        for row in rows:
            candidate = row.get(job.feed.asset_column)
            if not isinstance(candidate, str):
                continue
            asset_type_hint = None
            if job.feed.asset_type_column and isinstance(
                row.get(job.feed.asset_type_column), str
            ):
                asset_type_hint = row[job.feed.asset_type_column]
            try:
                asset_type, normalized = normalize_asset(candidate, asset_type_hint)
            except ValueError:
                LOG.debug(
                    "Skipping invalid asset",
                    extra={"value": candidate, "job_id": job.job_id},
                )
                continue
            assets.append(
                ReconAsset(
                    asset_type=asset_type,
                    normalized_value=normalized,
                    raw_value=candidate.strip(),
                    matched_scope=None,
                    metadata={},
                    first_seen=now,
                    last_seen=now,
                )
            )
        return assets

    def _extract_from_items(
        self, items: Iterable[Any], job: ReconJob, now: datetime
    ) -> List[ReconAsset]:
        assets: List[ReconAsset] = []
        for entry in items:
            if isinstance(entry, str):
                candidate_value = entry
                type_hint = None
            elif isinstance(entry, dict):
                candidate_value = entry.get(job.feed.asset_field)
                if not isinstance(candidate_value, str):
                    continue
                type_hint_value = entry.get(job.feed.type_field or "")
                type_hint = type_hint_value if isinstance(type_hint_value, str) else None
            else:
                continue
            try:
                asset_type, normalized = normalize_asset(candidate_value, type_hint)
            except ValueError:
                LOG.debug(
                    "Skipping invalid API asset",
                    extra={"value": candidate_value, "job_id": job.job_id},
                )
                continue
            assets.append(
                ReconAsset(
                    asset_type=asset_type,
                    normalized_value=normalized,
                    raw_value=candidate_value.strip(),
                    matched_scope=None,
                    metadata={},
                    first_seen=now,
                    last_seen=now,
                )
            )
        return assets

    def _retrieve_text(self, url: str, encoding: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme == "file":
            path = Path(parsed.path)
            return path.read_text(encoding=encoding)
        response = self._http.request("GET", url, timeout=self._config.http_timeout)
        response.raise_for_status()
        response.encoding = encoding
        return response.text

    def _retrieve_json(self, url: str, method: str) -> Any:
        parsed = urlparse(url)
        if parsed.scheme == "file":
            path = Path(parsed.path)
            return json.loads(path.read_text(encoding="utf-8"))
        response = self._http.request(
            method or "GET",
            url,
            timeout=self._config.http_timeout,
        )
        response.raise_for_status()
        return response.json()


__all__ = [
    "ReconAsset",
    "ReconFeed",
    "ReconJob",
    "ReconWorker",
    "WorkerConfig",
    "normalize_asset",
]


if __name__ == "__main__":  # pragma: no cover - CLI bootstrap
    config = WorkerConfig.load()
    worker = ReconWorker(config)
    worker.run_forever()
