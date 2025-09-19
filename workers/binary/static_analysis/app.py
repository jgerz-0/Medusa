"""Minimal FastAPI app exposing health endpoints for the static analysis worker."""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Medusa Binary Static Analysis Worker")


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    """Return a deterministic success payload for liveness probes."""

    return {"status": "ok"}
