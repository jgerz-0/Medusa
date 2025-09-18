# Medusa nuclei worker container
#
# Security considerations:
# - nuclei telemetry disabled by default.
# - runs as non-root user.
# - dependencies locked via Poetry.

FROM python:3.11-slim AS base

ENV POETRY_VERSION=1.7.1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \ 
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \ 
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - --version ${POETRY_VERSION} \
    && ln -s /root/.local/bin/poetry /usr/local/bin/poetry \
    && poetry config virtualenvs.create false

# Install nuclei binary
ARG NUCLEI_VERSION=3.1.10
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei-templates /tmp/LICENSE /tmp/README.md

WORKDIR /app

COPY pyproject.toml poetry.lock* ./

RUN poetry install --without dev --no-root

COPY . .

RUN useradd --create-home --shell /bin/bash worker \
    && chown -R worker:worker /app
USER worker

ENV NUCLEI_NO_TELEMETRY=true

ENTRYPOINT ["poetry", "run", "nuclei-worker"]
