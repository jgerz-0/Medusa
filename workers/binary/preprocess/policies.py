"""Policy enforcement primitives for binary preprocessing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from .inspection import FileDescriptor
from .schemas import BinaryPreprocessJob, PolicyDecision


class TriagePolicy(Protocol):
    """Interface implemented by preprocess triage policies."""

    def evaluate(
        self, job: BinaryPreprocessJob, descriptor: FileDescriptor
    ) -> PolicyDecision:
        ...


@dataclass
class AllowMimeTypesPolicy:
    """Allow-list policy enforcing approved MIME types."""

    allowed_mime_types: Iterable[str]

    def evaluate(
        self, job: BinaryPreprocessJob, descriptor: FileDescriptor
    ) -> PolicyDecision:
        allowed = set(mime.lower() for mime in self.allowed_mime_types)
        mime_value = (descriptor.mime_type or "application/octet-stream").lower()
        if not allowed or mime_value in allowed:
            return PolicyDecision(allowed=True)
        return PolicyDecision(
            allowed=False,
            reasons=[
                "mime_type_not_allowed",
                f"detected_mime={mime_value}",
            ],
        )


@dataclass
class MaxFileSizePolicy:
    """Fail closed when binaries exceed the configured size limit."""

    max_bytes: int

    def evaluate(
        self, job: BinaryPreprocessJob, descriptor: FileDescriptor
    ) -> PolicyDecision:
        if self.max_bytes <= 0:
            return PolicyDecision(allowed=True)
        if descriptor.size <= self.max_bytes:
            return PolicyDecision(allowed=True)
        return PolicyDecision(
            allowed=False,
            reasons=[
                "file_too_large",
                f"detected_size={descriptor.size}",
                f"max_bytes={self.max_bytes}",
            ],
        )


class PolicySuite:
    """Aggregate multiple policies into a single deterministic decision."""

    def __init__(self, policies: Iterable[TriagePolicy]):
        self._policies = list(policies)

    def evaluate(
        self, job: BinaryPreprocessJob, descriptor: FileDescriptor
    ) -> PolicyDecision:
        decision = PolicyDecision()
        for policy in self._policies:
            decision = decision.merge(policy.evaluate(job, descriptor))
        return decision


__all__ = [
    "AllowMimeTypesPolicy",
    "MaxFileSizePolicy",
    "PolicySuite",
    "TriagePolicy",
]
