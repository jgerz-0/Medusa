"""FastAPI application exposing worker diagnostics."""

from __future__ import annotations

from fastapi import Depends, FastAPI

from .worker import WorkerConfig

app = FastAPI(title="Medusa Binary Preprocess Worker", version="0.1.0")


def get_worker_config() -> WorkerConfig:
    return WorkerConfig.load()


@app.get("/healthz")
def health(config: WorkerConfig = Depends(get_worker_config)) -> dict[str, str]:
    return {"status": "ok", "queue": config.queue_key}


__all__ = ["app", "get_worker_config"]
