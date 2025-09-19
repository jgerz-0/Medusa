#
# Deterministic CVE enrichment worker container.
# - Installs dependencies via Poetry without creating virtualenvs.
# - Runs as non-root to reduce impact of container escape attempts.
# - Fetches advisories over HTTPS with pinned user-agent for auditability.

FROM python:3.11-slim AS base

ENV POETRY_VERSION=1.7.1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://install.python-poetry.org | python3 - --version ${POETRY_VERSION} \
    && ln -s /root/.local/bin/poetry /usr/local/bin/poetry \
    && poetry config virtualenvs.create false

WORKDIR /app

COPY pyproject.toml poetry.lock* ./

RUN poetry install --without dev --no-root

COPY . .

RUN useradd --create-home --shell /bin/bash worker \
    && chown -R worker:worker /app
USER worker

ENV CVE_ENRICHMENT_USER_AGENT="Medusa-CVE-Enrichment/0.1"

ENTRYPOINT ["poetry", "run", "cve-enrichment-worker"]
