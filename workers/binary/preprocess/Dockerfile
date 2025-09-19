# Binary preprocess worker container image
#
# Security considerations:
# - Installs libmagic to support deterministic MIME detection.
# - Uses Poetry with system site-packages to avoid hidden virtualenvs.
# - Drops to an unprivileged user for runtime parity with Kubernetes.

FROM python:3.11-slim AS base

ENV POETRY_VERSION=1.8.2 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libmagic1 file \
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

ENTRYPOINT ["poetry", "run", "python", "-m", "workers.binary.preprocess.worker"]
