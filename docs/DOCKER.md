# Docker Setup

This guide covers the Phase 1 local Docker Compose environment. It stands up every service referenced in the repository README so engineers can exercise the controller API, persistence tier, and analyst dashboard without hand-configuring dependencies.

## Requirements
- Docker Engine 20+
- Docker Compose V2
- 8 GB RAM available for containers
- 20 GB free disk space for container images, Postgres, MinIO, and Qdrant data directories

## Compose Manifests
- `infra/docker/docker-compose.yml` – boots Postgres, Redis, MinIO, Qdrant, the FastAPI controller, the nuclei, ZAP, and SQLMap workers, plus the Next.js frontend.
- `infra/docker/controller.Dockerfile` – Poetry-based image for the controller with Uvicorn hot reload enabled.
- `infra/docker/frontend.Dockerfile` – Node 20 + pnpm image for the dashboard.
- `infra/docker/.env.example` – sane defaults for development credentials and exposed ports.

All commands below assume you run them from the repository root unless otherwise noted.

## Bootstrap
```bash
cd infra/docker

# copy defaults and adjust secrets as needed
cp .env.example .env

# build all images and start the stack in the background
docker compose up --build -d

# verify each container reports healthy
docker compose ps

# capture the generated admin and analyst API keys for local tooling
docker compose exec controller cat /var/lib/medusa/principal_credentials.env
```

The `.env` file keeps the controller and workers aligned. Ensure the
following secrets are set before starting the stack:

- `MEDUSA_NUCLEI_CALLBACK_TOKEN`
- `MEDUSA_ZAP_CALLBACK_TOKEN`
- `MEDUSA_SQLMAP_CALLBACK_TOKEN`

Each worker reads the corresponding token via `NUCLEI_CALLBACK_TOKEN`,
`ZAP_CALLBACK_TOKEN`, or `SQLMAP_CALLBACK_TOKEN` so callbacks are rejected if a
container is misconfigured.

Set the optional `COMPOSE_BIN` environment variable if you prefer an alternate
Compose implementation (for example `podman compose`). The smoke test script
uses the same variable to avoid hard-coding the binary path.

The compose file automatically mounts code from `controller/`, `workers/web/nuclei/`, `workers/web/zap/`, `workers/web/sqlmap/`, and `frontend/` into the containers so edits on the host trigger FastAPI reloads, worker hot-reloads, and Next.js hot module updates. Postgres, Redis, MinIO, and Qdrant data persist under `infra/docker/data/` and survive container restarts. Principal API keys are written to `/var/lib/medusa/principal_credentials.env` inside the controller container and shared with the frontend so human analysts can authenticate without hard-coded secrets.

## Smoke Test
Run the end-to-end smoke test once the services report `healthy`:

```bash
./infra/docker/smoke-test.sh
```

The script requires a `.env` file in `infra/docker/` (copy `.env.example` before running) so that controller, worker, and smoke test credentials stay in sync. MinIO artifact uploads are disabled by default; set `NUCLEI_ARTIFACT_BUCKET` if you need to exercise S3 persistence locally.

The script performs the following actions:

- runs Alembic migrations to the latest revision,
- seeds demo targets if they are missing,
- creates a nuclei scan linked to the local smoke-test template,
- enqueues a job on Redis, and
- waits for the `nuclei-worker` container to call the controller callback using the shared secret from `.env`.

A successful run prints `Worker callback confirmed` and exits `0`. If the callback fails (for example, the worker cannot reach the controller or the callback token is misconfigured) the script exits non-zero with context so you can inspect `docker compose logs nuclei-worker controller`.

The MinIO console is available at `http://localhost:9001` with credentials from `.env`. Qdrant's HTTP API listens on `http://localhost:6333` for enrichment debugging.

### Dashboard login

When you visit `http://localhost:3000` the browser prompts for HTTP basic authentication. The Compose defaults set `DASHBOARD_BASIC_USER=analyst` and `DASHBOARD_BASIC_PASSWORD=analyst`; update or rotate them in `.env` before exposing the stack anywhere beyond isolated development.

## Troubleshooting
- `docker compose logs -f <service>` – inspect runtime logs (controller logs include audit events).
- `docker compose exec postgres psql -U $MEDUSA_POSTGRES_USER -d $MEDUSA_POSTGRES_DB -c "\dt"` – verify tables after migrations.
- `docker compose exec frontend pnpm install` – repopulate `node_modules` if the dashboard fails to start after dependency changes.
- `docker compose down -v` – tear down the stack and wipe all persistent volumes for a clean slate.

If Compose exits early, validate the manifest with `docker compose config` and ensure another process is not already binding ports `5432`, `6379`, `9000-9001`, `6333-6334`, `8000`, or `3000`.

## Security Notes
- The compose network is isolated to localhost, but scanners must still respect the authorized scope enforced by the controller.
- Credentials in `.env` are for local development only; rotate them frequently and use a secrets manager in staging/production.
- Keep Docker Desktop/Engine patched to the latest stable release before targeting external assets.

