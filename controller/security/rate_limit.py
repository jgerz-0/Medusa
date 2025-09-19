"""Simple in-memory rate limiter for controller endpoints."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, Optional, Tuple


@dataclass
class RateLimitResult:
    allowed: bool
    metadata: Dict[str, int]


@dataclass
class RateLimiter:
    """Token bucket style limiter shared across controller workers."""

    max_requests: int
    window_seconds: int
    exempt_subjects: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}

    def is_enabled(self) -> bool:
        return self.max_requests > 0 and self.window_seconds > 0

    def is_exempt(self, subject: str) -> bool:
        return subject in self.exempt_subjects

    def allow(self, key: str, *, now: Optional[float] = None) -> RateLimitResult:
        if not self.is_enabled():
            return RateLimitResult(True, {"limit": self.max_requests, "window": self.window_seconds})

        current_time = now if now is not None else time.monotonic()
        window_start = current_time - self.window_seconds

        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] <= window_start:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(0.0, self.window_seconds - (current_time - bucket[0]))
                retry_seconds = int(retry_after) if retry_after.is_integer() else int(retry_after) + 1
                metadata = {
                    "limit": self.max_requests,
                    "window": self.window_seconds,
                    "retry_after": retry_seconds,
                }
                return RateLimitResult(False, metadata)

            bucket.append(current_time)
            remaining = self.max_requests - len(bucket)

        metadata = {
            "limit": self.max_requests,
            "window": self.window_seconds,
            "remaining": remaining,
        }
        return RateLimitResult(True, metadata)

    @classmethod
    def from_settings(
        cls,
        *,
        max_requests: int,
        window_seconds: int,
        exempt_subjects: Iterable[str],
    ) -> "RateLimiter":
        normalized_exempt = tuple(sorted({subject for subject in exempt_subjects}))
        return cls(max_requests=max_requests, window_seconds=window_seconds, exempt_subjects=normalized_exempt)
