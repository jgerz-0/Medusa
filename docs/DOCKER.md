# Docker Setup (Work in Progress)

This guide covers the Phase 1 local Docker Compose environment. It stands up every service referenced in the repository README so engineers can exercise the controller API, persistence tier, and analyst dashboard without hand-configuring dependencies.

## Requirements
- Docker Engine 20+
- Docker Compose V2
- 8 GB RAM available for containers
- 20 GB free disk space for container images, Postgres, MinIO, and Qdrant data directories

## Compose Manifests
- `infra/docker/docker-compose.yml` – boots Postgres, Redis, MinIO, Qdrant, the FastAPI controller, and the Next.js frontend.
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
```

The compose file automatically mounts code from `controller/` and `frontend/` into the containers so edits on the host trigger FastAPI reloads and Next.js hot module updates. Postgres, Redis, MinIO, and Qdrant data persist under `infra/docker/data/` and survive container restarts.

## Smoke Test
Run the following once the services report `healthy`:

```bash
# run database migrations before hitting the API
docker compose exec controller poetry run alembic upgrade head

# seed sample targets for the dashboard
docker compose exec controller poetry run python scripts/seed_targets.py

# confirm controller API responds
curl http://localhost:8000/docs

# confirm the dashboard renders server-side data
curl -I http://localhost:3000/scans
```

The MinIO console is available at `http://localhost:9001` with credentials from `.env`. Qdrant's HTTP API listens on `http://localhost:6333` for enrichment debugging.

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

