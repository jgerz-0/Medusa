"""Minimal FastAPI application for the angr symbolic execution worker."""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Medusa Binary Symbolic Execution Worker")


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    """Return a deterministic health payload for liveness probes."""

    return {"status": "ok"}
