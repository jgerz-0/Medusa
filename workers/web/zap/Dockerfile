# Medusa ZAP worker container
#
# Key hardening choices:
# - Base on the upstream OWASP ZAP image for maintained signatures.
# - Run the worker as a non-root user.
# - Restrict runtime dependencies to redis/requests.

FROM owasp/zap2docker-stable:2.12.0 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1 \
    ZAP_BINARY=/zap/zap-baseline.py

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir "poetry==${POETRY_VERSION}" \
    && poetry config virtualenvs.create false

RUN ln -s /zap/zap-baseline.py /usr/local/bin/zap-baseline.py

WORKDIR /app

COPY pyproject.toml poetry.lock* ./
RUN poetry install --without dev --no-root

COPY . .

RUN adduser --disabled-password --gecos "" worker \
    && chown -R worker:worker /app
USER worker

ENTRYPOINT ["poetry", "run", "zap-worker"]
