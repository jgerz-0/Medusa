"""Recon worker that ingests external inventory feeds and normalises assets."""

from __future__ import annotations

import csv
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
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
    subfinder_path: str = field(
        default_factory=lambda: os.getenv("RECON_SUBFINDER_PATH", "subfinder")
    )
    amass_path: str = field(
        default_factory=lambda: os.getenv("RECON_AMASS_PATH", "amass")
    )
    httpx_path: str = field(
        default_factory=lambda: os.getenv("RECON_HTTPX_PATH", "httpx")
    )
    tool_timeout: int = field(
        default_factory=lambda: int(os.getenv("RECON_TOOL_TIMEOUT", "120"))
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
class ReconTooling:
    subfinder: bool = True
    amass: bool = True
    httpx: bool = True
    httpx_ports: List[int] = field(default_factory=lambda: [80, 443, 8080])
    httpx_rate_limit: Optional[int] = None
    httpx_probe_tls: bool = True
    httpx_follow_redirects: bool = False

    def to_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "subfinder": self.subfinder,
            "amass": self.amass,
            "httpx": self.httpx,
            "httpx_ports": list(self.httpx_ports),
            "httpx_probe_tls": self.httpx_probe_tls,
            "httpx_follow_redirects": self.httpx_follow_redirects,
        }
        if self.httpx_rate_limit is not None:
            payload["httpx_rate_limit"] = self.httpx_rate_limit
        return payload

    @classmethod
    def from_json(cls, payload: Any) -> "ReconTooling":
        if not isinstance(payload, dict):
            return cls()
        ports: List[int] = []
        for candidate in payload.get("httpx_ports", []):
            try:
                port_value = int(candidate)
            except (TypeError, ValueError):
                continue
            if 1 <= port_value <= 65535 and port_value not in ports:
                ports.append(port_value)
        rate_limit_value = payload.get("httpx_rate_limit")
        rate_limit: Optional[int]
        try:
            rate_limit = int(rate_limit_value) if rate_limit_value is not None else None
        except (TypeError, ValueError):
            rate_limit = None
        return cls(
            subfinder=bool(payload.get("subfinder", True)),
            amass=bool(payload.get("amass", True)),
            httpx=bool(payload.get("httpx", True)),
            httpx_ports=ports or [80, 443, 8080],
            httpx_rate_limit=rate_limit,
            httpx_probe_tls=bool(payload.get("httpx_probe_tls", True)),
            httpx_follow_redirects=bool(payload.get("httpx_follow_redirects", False)),
        )


@dataclass
class ReconTargetSpec:
    scope: str
    asset_type: str
    seed_assets: List[str] = field(default_factory=list)
    target_id: Optional[str] = None
    name: Optional[str] = None

    def to_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "scope": self.scope,
            "asset_type": self.asset_type,
            "seed_assets": list(self.seed_assets),
        }
        if self.target_id:
            payload["target_id"] = self.target_id
        if self.name:
            payload["name"] = self.name
        return payload

    @classmethod
    def from_json(cls, payload: Any) -> Optional["ReconTargetSpec"]:
        if not isinstance(payload, dict):
            return None
        scope = str(payload.get("scope") or "").strip()
        if not scope:
            return None
        asset_type = str(payload.get("asset_type") or "domain").strip().lower()
        if asset_type not in {"domain", "ipv4", "ipv6"}:
            return None
        seeds: List[str] = []
        for candidate in payload.get("seed_assets", []):
            if isinstance(candidate, str):
                normalized = candidate.strip()
                if normalized and normalized not in seeds:
                    seeds.append(normalized)
        target_id = str(payload.get("target_id") or "").strip() or None
        name = str(payload.get("name") or "").strip() or None
        return cls(
            scope=scope,
            asset_type=asset_type,
            seed_assets=seeds,
            target_id=target_id,
            name=name,
        )


@dataclass
class ReconExecution:
    mode: str = "feed"
    targets: List[ReconTargetSpec] = field(default_factory=list)
    tooling: ReconTooling = field(default_factory=ReconTooling)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "targets": [target.to_payload() for target in self.targets],
            "tools": self.tooling.to_payload(),
        }

    @classmethod
    def from_json(cls, payload: Any) -> "ReconExecution":
        if not isinstance(payload, dict):
            return cls()
        mode = str(payload.get("mode") or "feed").strip().lower()
        if mode not in {"feed", "active"}:
            mode = "feed"
        tooling = ReconTooling.from_json(payload.get("tools"))
        targets: List[ReconTargetSpec] = []
        if mode == "active":
            for item in payload.get("targets", []):
                target = ReconTargetSpec.from_json(item)
                if target is not None:
                    targets.append(target)
        return cls(mode=mode, targets=targets, tooling=tooling)


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
    execution: "ReconExecution" = field(default_factory=lambda: ReconExecution(mode="feed"))

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
        feed: Optional[ReconFeed] = None

        if isinstance(feed_payload, dict):
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

        execution_payload = data.get("execution")
        execution = ReconExecution.from_json(execution_payload)

        if feed is None:
            if execution.mode != "active":
                raise ValueError("Feed configuration required for non-active recon jobs")
            feed = ReconFeed(type="csv", url="")

        return cls(
            job_id=job_id,
            source=source,
            feed=feed,
            authorized_scopes=scopes,
            labels=labels,
            callback_url=callback_url,
            requested_by=requested_by,
            queued_at=queued_at,
            execution=execution,
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
        process_runner: Optional[
            Callable[..., subprocess.CompletedProcess[str]]
        ] = None,
    ) -> None:
        if requests is None:  # pragma: no cover - runtime guard
            raise RuntimeError("requests package is required to run the recon worker")
        if redis is None and redis_client is None:  # pragma: no cover - runtime guard
            raise RuntimeError("redis package is required to run the recon worker")

        self._config = config
        self._redis = redis_client
        self._http = http_session or requests.Session()
        self._active_engine = ActiveReconEngine(config, runner=process_runner)

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
            "authorized_scopes": list(job.authorized_scopes),
            "execution": job.execution.to_payload(),
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

    def _enumerate_active(self, job: ReconJob, now: datetime) -> List[ReconAsset]:
        try:
            return self._active_engine.enumerate(job, now)
        except Exception:  # pragma: no cover - defensive guard
            LOG.exception(
                "Active recon execution failed",
                extra={"job_id": job.job_id, "source": job.source},
            )
            return []

    def collect_assets(self, job: ReconJob) -> List[ReconAsset]:
        now = datetime.now(tz=timezone.utc)
        entries: List[ReconAsset] = []
        if job.execution.mode == "active":
            entries.extend(self._enumerate_active(job, now))
        else:
            if job.feed.type == "csv" and job.feed.url:
                rows = self._load_csv(job.feed)
                entries.extend(self._extract_from_rows(rows, job, now))
            elif job.feed.type == "api" and job.feed.url:
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


class ActiveReconEngine:
    """Execute deterministic recon tooling against authorized targets."""

    def __init__(
        self,
        config: WorkerConfig,
        *,
        runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None,
    ) -> None:
        self._config = config
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(
        command: List[str],
        *,
        capture_output: bool = True,
        text: bool = True,
        check: bool = False,
        timeout: Optional[int] = None,
        input: Optional[str] = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603,S607 - commands are composed from fixed allow-list
            command,
            capture_output=capture_output,
            text=text,
            check=check,
            timeout=timeout,
            input=input,
        )

    def enumerate(self, job: ReconJob, now: datetime) -> List[ReconAsset]:
        assets: List[ReconAsset] = []
        tooling = job.execution.tooling
        for target in job.execution.targets:
            host_map = self._collect_hosts(target, tooling)
            if host_map:
                assets.extend(self._hosts_to_assets(target, host_map, now))
            if tooling.httpx:
                assets.extend(self._httpx_assets(target, host_map, tooling, now))
        return assets

    def _collect_hosts(
        self, target: ReconTargetSpec, tooling: ReconTooling
    ) -> Dict[str, Dict[str, Any]]:
        hosts: Dict[str, Dict[str, Any]] = {}

        def record(candidate: str, source: str) -> None:
            value = (candidate or "").strip()
            if not value:
                return
            key = value.lower().rstrip(".") if target.asset_type == "domain" else value
            entry = hosts.setdefault(
                key,
                {
                    "sources": [],
                    "raw_values": set(),
                },
            )
            entry["raw_values"].add(value)
            sources = entry.setdefault("sources", [])
            if source not in sources:
                sources.append(source)

        record(target.scope, "target-scope")
        for seed in target.seed_assets:
            record(seed, "seed")

        if target.asset_type == "domain":
            if tooling.subfinder:
                for host in self._run_subfinder(target.scope):
                    record(host, "subfinder")
            if tooling.amass:
                for host in self._run_amass(target.scope):
                    record(host, "amass")

        return hosts

    def _hosts_to_assets(
        self,
        target: ReconTargetSpec,
        host_map: Dict[str, Dict[str, Any]],
        now: datetime,
    ) -> List[ReconAsset]:
        assets: List[ReconAsset] = []
        type_hint = target.asset_type if target.asset_type in {"ipv4", "ipv6"} else "domain"
        for entry in host_map.values():
            raw_values = entry.get("raw_values", {target.scope})
            selected = sorted(raw_values)[0]
            try:
                asset_type, normalized_value = normalize_asset(selected, type_hint)
            except ValueError:
                LOG.debug(
                    "Skipping invalid recon host",
                    extra={"value": selected, "target_scope": target.scope},
                )
                continue
            sources = sorted(set(entry.get("sources", [])))
            if "target-scope" not in sources:
                sources.append("target-scope")
            metadata: Dict[str, Any] = {
                "sources": sources,
                "target_scope": target.scope,
            }
            if target.target_id:
                metadata["target_id"] = target.target_id
            if target.name:
                metadata["target_name"] = target.name
            assets.append(
                ReconAsset(
                    asset_type=asset_type,
                    normalized_value=normalized_value,
                    raw_value=selected,
                    matched_scope=None,
                    metadata=metadata,
                    first_seen=now,
                    last_seen=now,
                )
            )
        return assets

    def _httpx_assets(
        self,
        target: ReconTargetSpec,
        host_map: Dict[str, Dict[str, Any]],
        tooling: ReconTooling,
        now: datetime,
    ) -> List[ReconAsset]:
        if not host_map:
            return []
        hosts = sorted(host_map.keys())
        results = self._run_httpx(hosts, tooling)
        assets: List[ReconAsset] = []
        for result in results:
            url = result.get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            try:
                asset_type, normalized_value = normalize_asset(url, "url")
            except ValueError:
                LOG.debug(
                    "Skipping invalid httpx result",
                    extra={"url": url, "target_scope": target.scope},
                )
                continue
            metadata: Dict[str, Any] = {
                "sources": ["httpx"],
                "target_scope": target.scope,
            }
            host = result.get("host")
            if isinstance(host, str) and host.strip():
                metadata["host"] = host.strip()
            if target.target_id:
                metadata["target_id"] = target.target_id
            if target.name:
                metadata["target_name"] = target.name
            port = result.get("port")
            if isinstance(port, int) and 1 <= port <= 65535:
                metadata["port"] = port
            service: Dict[str, Any] = {}
            for key in ("status_code", "webserver", "technologies", "tls", "ip"):
                value = result.get(key)
                if value in (None, [], ""):
                    continue
                service[key] = value
            if service:
                metadata["service"] = service
            assets.append(
                ReconAsset(
                    asset_type=asset_type,
                    normalized_value=normalized_value,
                    raw_value=url.strip(),
                    matched_scope=None,
                    metadata=metadata,
                    first_seen=now,
                    last_seen=now,
                )
            )
        return assets

    def _run_subfinder(self, scope: str) -> List[str]:
        command = [
            self._config.subfinder_path,
            "-silent",
            "-json",
            "-d",
            scope,
        ]
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._config.tool_timeout,
            )
        except Exception:  # pragma: no cover - defensive guard
            LOG.exception("Failed to execute subfinder", extra={"scope": scope})
            return []
        if completed.returncode not in (0, None):
            LOG.warning(
                "subfinder exited with a non-zero status",
                extra={"scope": scope, "returncode": completed.returncode},
            )
            return []
        return self._parse_subfinder_output(completed.stdout)

    def _run_amass(self, scope: str) -> List[str]:
        command = [
            self._config.amass_path,
            "enum",
            "-passive",
            "-d",
            scope,
            "-o",
            "-",
        ]
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._config.tool_timeout,
            )
        except Exception:  # pragma: no cover - defensive guard
            LOG.exception("Failed to execute amass", extra={"scope": scope})
            return []
        if completed.returncode not in (0, None):
            LOG.warning(
                "amass exited with a non-zero status",
                extra={"scope": scope, "returncode": completed.returncode},
            )
            return []
        return self._parse_amass_output(completed.stdout)

    def _run_httpx(
        self, hosts: List[str], tooling: ReconTooling
    ) -> List[Dict[str, Any]]:
        if not hosts:
            return []
        command: List[str] = [
            self._config.httpx_path,
            "-json",
            "-silent",
            "-no-color",
        ]
        if tooling.httpx_ports:
            ports = [str(port) for port in tooling.httpx_ports if 1 <= int(port) <= 65535]
            if ports:
                command.extend(["-ports", ",".join(ports)])
        if tooling.httpx_rate_limit:
            command.extend(["-rate", str(tooling.httpx_rate_limit)])
        if tooling.httpx_probe_tls:
            command.append("-tls-probe")
        if tooling.httpx_follow_redirects:
            command.append("-follow-redirects")

        input_payload = "\n".join(hosts) + "\n"
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._config.tool_timeout,
                input=input_payload,
            )
        except Exception:  # pragma: no cover - defensive guard
            LOG.exception("Failed to execute httpx", extra={"host_count": len(hosts)})
            return []
        if completed.returncode not in (0, None):
            LOG.warning(
                "httpx exited with a non-zero status",
                extra={"returncode": completed.returncode},
            )
            return []
        return self._parse_httpx_output(completed.stdout)

    @staticmethod
    def _parse_subfinder_output(stdout: str) -> List[str]:
        hosts: List[str] = []
        for line in stdout.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                value = candidate
            else:
                value = (
                    parsed.get("host")
                    or parsed.get("input")
                    or parsed.get("value")
                    or parsed.get("name")
                    or parsed.get("url")
                )
                if not isinstance(value, str):
                    continue
                value = value.strip()
            if value and value not in hosts:
                hosts.append(value)
        return hosts

    @staticmethod
    def _parse_amass_output(stdout: str) -> List[str]:
        hosts: List[str] = []
        for line in stdout.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            if candidate not in hosts:
                hosts.append(candidate)
        return hosts

    @staticmethod
    def _parse_httpx_output(stdout: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            try:
                data = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            url = data.get("url") or data.get("input")
            if not isinstance(url, str) or not url.strip():
                continue
            host = data.get("host") or data.get("input")
            host_value = host.strip() if isinstance(host, str) else None
            port_value = data.get("port")
            try:
                port = int(port_value) if port_value is not None else None
            except (TypeError, ValueError):
                port = None
            status_candidate = data.get("status-code") or data.get("status_code")
            try:
                status_code = int(status_candidate) if status_candidate is not None else None
            except (TypeError, ValueError):
                status_code = None
            technologies_raw = data.get("technologies") or data.get("tech")
            technologies: List[str] = []
            if isinstance(technologies_raw, list):
                for tech in technologies_raw:
                    tech_value = str(tech).strip()
                    if tech_value and tech_value not in technologies:
                        technologies.append(tech_value)
            elif isinstance(technologies_raw, str):
                normalized = technologies_raw.strip()
                if normalized:
                    technologies.append(normalized)
            webserver = data.get("webserver") or data.get("title")
            if isinstance(webserver, str):
                webserver = webserver.strip()
            tls_enabled = bool(data.get("tls"))
            ip_value = data.get("ip") or data.get("a")
            ip_address_value = ip_value.strip() if isinstance(ip_value, str) else None
            results.append(
                {
                    "url": url.strip(),
                    "host": host_value,
                    "port": port,
                    "status_code": status_code,
                    "webserver": webserver if isinstance(webserver, str) and webserver else None,
                    "technologies": technologies,
                    "tls": tls_enabled,
                    "ip": ip_address_value,
                }
            )
        return results


__all__ = [
    "ReconAsset",
    "ReconFeed",
    "ReconJob",
    "ReconExecution",
    "ReconTargetSpec",
    "ReconTooling",
    "ReconWorker",
    "WorkerConfig",
    "normalize_asset",
]


if __name__ == "__main__":  # pragma: no cover - CLI bootstrap
    config = WorkerConfig.load()
    worker = ReconWorker(config)
    worker.run_forever()
