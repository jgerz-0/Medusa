"""Minimal Prometheus-style metrics primitives for the controller service."""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, Tuple

CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


class MetricsRegistry:
    """Registry that tracks metric instances in insertion order."""

    def __init__(self) -> None:
        self._metrics: Dict[str, Metric] = {}

    def register(self, metric: "Metric") -> None:
        if metric.name in self._metrics:
            raise ValueError(f"Metric {metric.name} already registered")
        self._metrics[metric.name] = metric

    def __iter__(self) -> Iterator["Metric"]:
        return iter(self._metrics.values())


@dataclass(frozen=True)
class MetricKey:
    """Normalized label key for metric samples."""

    values: Tuple[str, ...]


class Metric:
    """Base class for metrics."""

    metric_type: str

    def __init__(self, name: str, description: str, label_names: Iterable[str]) -> None:
        self.name = name
        self.description = description
        self.label_names = tuple(label_names)

    def _build_key(self, labels: Dict[str, object]) -> MetricKey:
        if set(labels.keys()) != set(self.label_names):
            expected = ", ".join(self.label_names)
            provided = ", ".join(labels.keys())
            raise ValueError(f"Labels mismatch for {self.name}: expected [{expected}], got [{provided}]")
        ordered = tuple(str(labels[label]) for label in self.label_names)
        return MetricKey(ordered)

    def _format_labels(self, key: MetricKey, extra: Dict[str, object] | None = None) -> str:
        label_pairs = [
            f'{name}="{value}"'
            for name, value in zip(self.label_names, key.values, strict=True)
        ]
        if extra:
            label_pairs.extend(f'{k}="{v}"' for k, v in extra.items())
        if not label_pairs:
            return ""
        return "{" + ",".join(label_pairs) + "}"

    def render_samples(self) -> Iterator[str]:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError


class CounterMetric(Metric):
    metric_type = "counter"

    def __init__(self, name: str, description: str, label_names: Iterable[str]) -> None:
        super().__init__(name, description, label_names)
        self._values: Dict[MetricKey, float] = {}

    def labels(self, **labels: object) -> "CounterChild":
        key = self._build_key(labels)
        return CounterChild(self, key)

    def inc(self, key: MetricKey, amount: float = 1.0) -> None:
        self._values[key] = self._values.get(key, 0.0) + amount

    def render_samples(self) -> Iterator[str]:
        for key, value in sorted(self._values.items(), key=lambda item: item[0].values):
            labels_str = self._format_labels(key)
            yield f"{self.name}{labels_str} {value:.6f}"


class CounterChild:
    def __init__(self, parent: CounterMetric, key: MetricKey) -> None:
        self._parent = parent
        self._key = key

    def inc(self, amount: float = 1.0) -> None:
        self._parent.inc(self._key, amount)


class HistogramMetric(Metric):
    metric_type = "histogram"

    def __init__(
        self,
        name: str,
        description: str,
        label_names: Iterable[str],
        buckets: Iterable[float],
    ) -> None:
        super().__init__(name, description, label_names)
        ordered = sorted(float(bound) for bound in buckets)
        if not ordered or ordered[-1] == float("inf"):
            self.buckets = tuple(ordered)
        else:
            self.buckets = tuple(ordered)
        self._samples: Dict[MetricKey, Dict[str, object]] = {}

    def labels(self, **labels: object) -> "HistogramChild":
        key = self._build_key(labels)
        return HistogramChild(self, key)

    def observe(self, key: MetricKey, value: float) -> None:
        sample = self._samples.setdefault(
            key,
            {
                "buckets": [0.0 for _ in range(len(self.buckets) + 1)],
                "count": 0.0,
                "sum": 0.0,
            },
        )
        bucket_counts = sample["buckets"]
        index = bisect_left(self.buckets, value)
        for i in range(index, len(self.buckets)):
            bucket_counts[i] += 1.0
        bucket_counts[-1] += 1.0
        sample["count"] += 1.0
        sample["sum"] += value

    def render_samples(self) -> Iterator[str]:
        for key in sorted(self._samples.keys(), key=lambda item: item.values):
            sample = self._samples[key]
            bucket_counts = sample["buckets"]
            for idx, bound in enumerate(self.buckets):
                labels = self._format_labels(key, {"le": bound})
                yield f"{self.name}_bucket{labels} {bucket_counts[idx]:.6f}"
            labels = self._format_labels(key, {"le": "+Inf"})
            yield f"{self.name}_bucket{labels} {bucket_counts[-1]:.6f}"
            yield f"{self.name}_sum{self._format_labels(key)} {sample['sum']:.6f}"
            yield f"{self.name}_count{self._format_labels(key)} {sample['count']:.6f}"


class HistogramChild:
    def __init__(self, parent: HistogramMetric, key: MetricKey) -> None:
        self._parent = parent
        self._key = key

    def observe(self, value: float) -> None:
        self._parent.observe(self._key, value)


METRICS_REGISTRY = MetricsRegistry()

REQUEST_COUNTER = CounterMetric(
    "medusa_controller_http_requests_total",
    "Total HTTP requests processed by the Medusa controller.",
    ("method", "endpoint", "status_code"),
)
METRICS_REGISTRY.register(REQUEST_COUNTER)

REQUEST_LATENCY = HistogramMetric(
    "medusa_controller_http_request_duration_seconds",
    "Latency histogram for Medusa controller HTTP requests.",
    ("method", "endpoint", "status_code"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0),
)
METRICS_REGISTRY.register(REQUEST_LATENCY)

AUDIT_EVENT_COUNTER = CounterMetric(
    "medusa_audit_events_total",
    "Audit log events recorded by action name.",
    ("action",),
)
METRICS_REGISTRY.register(AUDIT_EVENT_COUNTER)

JOB_ENQUEUED_COUNTER = CounterMetric(
    "medusa_jobs_enqueued_total",
    "Jobs enqueued by the controller, labelled by job type.",
    ("job_type",),
)
METRICS_REGISTRY.register(JOB_ENQUEUED_COUNTER)

WORKER_CALLBACK_COUNTER = CounterMetric(
    "medusa_worker_callbacks_total",
    "Callbacks processed from asynchronous workers.",
    ("worker",),
)
METRICS_REGISTRY.register(WORKER_CALLBACK_COUNTER)

WORKER_ITEM_COUNTER = CounterMetric(
    "medusa_worker_callback_items_total",
    "Payload items (findings, advisories) persisted from worker callbacks.",
    ("worker",),
)
METRICS_REGISTRY.register(WORKER_ITEM_COUNTER)


def render_latest() -> bytes:
    """Return the current registry snapshot in Prometheus text format."""

    lines = []
    for metric in METRICS_REGISTRY:
        lines.append(f"# HELP {metric.name} {metric.description}")
        lines.append(f"# TYPE {metric.name} {metric.metric_type}")
        lines.extend(metric.render_samples())
    return ("\n".join(lines) + "\n").encode("utf-8")


def observe_http_request(
    *, method: str, endpoint: str, status_code: int, duration_seconds: float
) -> None:
    """Track request counters and latency for HTTP traffic."""

    label_status = str(status_code)
    REQUEST_COUNTER.labels(method=method, endpoint=endpoint, status_code=label_status).inc()
    REQUEST_LATENCY.labels(
        method=method, endpoint=endpoint, status_code=label_status
    ).observe(duration_seconds)


def record_audit_event(action: str) -> None:
    """Increment the audit event counter for the supplied action."""

    AUDIT_EVENT_COUNTER.labels(action=action).inc()


def record_job_enqueued(job_type: str) -> None:
    """Count a newly enqueued background job (scan, enrichment, etc.)."""

    JOB_ENQUEUED_COUNTER.labels(job_type=job_type).inc()


def record_worker_callback(worker: str, items_persisted: int) -> None:
    """Track worker callback invocations and persisted payload counts."""

    WORKER_CALLBACK_COUNTER.labels(worker=worker).inc()
    if items_persisted > 0:
        WORKER_ITEM_COUNTER.labels(worker=worker).inc(float(items_persisted))


__all__ = [
    "AUDIT_EVENT_COUNTER",
    "CONTENT_TYPE_LATEST",
    "JOB_ENQUEUED_COUNTER",
    "METRICS_REGISTRY",
    "REQUEST_COUNTER",
    "REQUEST_LATENCY",
    "WORKER_CALLBACK_COUNTER",
    "WORKER_ITEM_COUNTER",
    "observe_http_request",
    "record_audit_event",
    "record_job_enqueued",
    "record_worker_callback",
    "render_latest",
]
