# Anomaly detection worker image used for local Compose deployments.
# Installs the controller package so the worker can inspect audit logs securely.
FROM python:3.11-slim AS base

ENV POETRY_VERSION=1.8.2 \
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

ENTRYPOINT ["poetry", "run", "python", "-m", "workers.anomaly.worker"]
