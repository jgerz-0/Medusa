"""FastAPI health endpoint for the binary fuzzing worker."""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Medusa Binary Fuzzing Worker")


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    """Return a deterministic success payload for liveness probes."""

    return {"status": "ok"}
