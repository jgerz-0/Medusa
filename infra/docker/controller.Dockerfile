# syntax=docker/dockerfile:1
# Controller image for local Compose development.
# Uses Poetry to install dependencies and runs Uvicorn in reload mode.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.8.2 \
    POETRY_VIRTUALENVS_CREATE=false

# Install system dependencies required by psycopg binary wheels and build tooling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "poetry==${POETRY_VERSION}" "uvicorn[standard]==0.27.1"

WORKDIR /app/controller

# Install Python dependencies first for better build caching.
COPY controller/pyproject.toml ./pyproject.toml
RUN poetry install --no-root

# Copy the controller application code.
COPY controller/ ./

# Provide a non-root user for local dev parity with hardened deployments.
RUN useradd --create-home --shell /bin/bash medusa
USER medusa

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
