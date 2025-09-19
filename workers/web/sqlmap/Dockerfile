# Medusa SQLMap worker container
#
# Security choices:
# - Install sqlmap from the Debian repositories.
# - Run as non-root and keep dependencies minimal.

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1 \
    SQLMAP_BINARY=/usr/bin/sqlmap

RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlmap python3-venv build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}" \
    && poetry config virtualenvs.create false

WORKDIR /app

COPY pyproject.toml poetry.lock* ./
RUN poetry install --without dev --no-root

COPY . .

RUN adduser --disabled-password --gecos "" worker \
    && chown -R worker:worker /app
USER worker

ENTRYPOINT ["poetry", "run", "sqlmap-worker"]
