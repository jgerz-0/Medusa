"""Container runtime helpers hardened with allow-listed flags."""

from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Mapping, MutableSequence, Optional, Sequence

LOG = logging.getLogger("medusa.workers.binary.static_analysis.runtime")

DEFAULT_ALLOWED_FLAGS: tuple[str, ...] = (
    "--rm",
    "--network=none",
    "--user",
    "--cpus",
    "--memory",
    "--pids-limit",
    "--security-opt",
    "-v",
)


@dataclass
class RuntimeConfig:
    """Configuration describing the container runtime invocation."""

    binary: str = "docker"
    base_flags: Sequence[str] = field(
        default_factory=lambda: ("--rm", "--network=none")
    )
    allowed_flags: Sequence[str] = field(default_factory=lambda: DEFAULT_ALLOWED_FLAGS)

    def validate_flags(self, flags: Iterable[str]) -> List[str]:
        """Ensure the supplied flags fall within the approved allow-list."""

        validated: List[str] = []
        allowed = set(self.allowed_flags)
        iterator = iter(flags)
        for token in iterator:
            if token.startswith("-v") and token != "-v":
                # Support shorthand "-v=/path" for docker/podman.
                flag, value = token.split("=", 1)
                if flag not in allowed:
                    raise ValueError(
                        f"Flag {flag} is not permitted for the container runtime"
                    )
                validated.extend([flag, value])
                continue

            if "=" in token:
                flag, value = token.split("=", 1)
                if flag not in allowed:
                    raise ValueError(
                        f"Flag {flag} is not permitted for the container runtime"
                    )
                validated.extend([flag, value])
                continue

            if token not in allowed:
                raise ValueError(
                    f"Flag {token} is not permitted for the container runtime"
                )
            validated.append(token)

            if token == "-v":
                # Volume mounts require an accompanying value; allowlist does not include the path.
                try:
                    value = next(iterator)
                except StopIteration as exc:  # pragma: no cover - defensive guard
                    raise ValueError(
                        "Volume flag -v requires a mount specification"
                    ) from exc
                validated.append(value)
        return validated


class ContainerRunner:
    """Wrapper around docker/podman enforcing deterministic runtime flags."""

    def __init__(self, config: RuntimeConfig) -> None:
        self._config = config

    def run(
        self,
        image: str,
        command: Sequence[str],
        *,
        mounts: Mapping[Path, str],
        extra_flags: Optional[Sequence[str]] = None,
        environment: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a containerized command with constrained options."""

        base_cmd: MutableSequence[str] = [self._config.binary, "run"]
        base_cmd.extend(self._config.validate_flags(self._config.base_flags))

        if extra_flags:
            base_cmd.extend(self._config.validate_flags(extra_flags))

        for host_path, container_path in mounts.items():
            mount_spec = f"{host_path}:{container_path}"
            base_cmd.extend(["-v", mount_spec])

        base_cmd.append(image)
        base_cmd.extend(command)

        LOG.debug(
            "Executing container runtime", extra={"command": shlex.join(base_cmd)}
        )
        completed = subprocess.run(  # noqa: S603 - runtime is allow-listed above
            base_cmd,
            check=False,
            capture_output=True,
            text=True,
            env=dict(environment or {}),
            timeout=timeout,
        )
        return completed


__all__ = ["ContainerRunner", "RuntimeConfig", "DEFAULT_ALLOWED_FLAGS"]
