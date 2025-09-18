# Docker Setup

This guide covers the local Docker Compose environment used during Phase 1 foundations.

## Requirements
- Docker Engine 20+
- Docker Compose V2
- 8 GB RAM available for containers

## Services
- `controller`: FastAPI API server
- `redis`: job queue broker
- `postgres`: relational datastore for scans and findings
- `minio`: artifact object storage
- `qdrant`: vector store for enrichment metadata
- `frontend`: Next.js analyst dashboard

## Usage
```bash
# start the environment
docker compose up -d

# view container status
docker compose ps

# tail controller logs
docker compose logs -f controller
```

## Configuration
- Copy `infra/docker/.env.example` to `infra/docker/.env` and review credentials.
- Postgres data persists under `infra/docker/data/postgres`. Delete intentionally if you need a clean slate.
- MinIO exposes the console on `http://localhost:9001`; generate access keys scoped to local testing.

## Security Notes
- Compose files default to bridge networking; scanners should only reach approved targets defined in `.env` scope lists.
- Secrets in `.env` are for local development only. Production credentials must come from a secrets manager.
- Ensure Docker Desktop or Engine is patched to the latest stable release before running external scans.
