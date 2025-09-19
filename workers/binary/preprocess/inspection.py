"""File inspection utilities for the binary preprocess worker."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

LOG = logging.getLogger("medusa.workers.binary.preprocess.inspection")

try:  # pragma: no cover - optional dependency for runtime deployments
    import magic  # type: ignore[import]
except Exception:  # pragma: no cover
    magic = None  # type: ignore[assignment]


@dataclass
class FileDescriptor:
    """Structured metadata extracted from a binary object."""

    sha256: str
    size: int
    mime_type: str
    magic_label: Optional[str]


class MagicFileInspector:
    """Perform file-type detection using python-magic with safe fallbacks."""

    def __init__(self, *, magic_module=None) -> None:
        self._magic = magic_module if magic_module is not None else magic

    def identify(self, payload: bytes) -> FileDescriptor:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be raw bytes")

        sha256 = hashlib.sha256(payload).hexdigest()
        size = len(payload)

        mime_type = "application/octet-stream"
        magic_label: Optional[str] = None

        if self._magic is None:
            LOG.warning(
                "python-magic not available; defaulting mime_type to application/octet-stream"
            )
        else:
            try:
                mime_type = str(self._magic.from_buffer(payload, mime=True))
                magic_label = str(self._magic.from_buffer(payload))
            except Exception as exc:  # pragma: no cover - defensive logging
                LOG.exception("magic detection failed: %s", exc)

        return FileDescriptor(
            sha256=sha256,
            size=size,
            mime_type=mime_type,
            magic_label=magic_label,
        )


__all__ = ["FileDescriptor", "MagicFileInspector"]
