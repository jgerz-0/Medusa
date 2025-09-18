# Docker Setup (Work in Progress)

Phase 1 does not yet ship Docker Compose manifests. This document captures the interim container commands so engineers can run
individual services without waiting for the declarative stack.

## Requirements
- Docker Engine 20+
- 8 GB RAM available for containers (leave headroom for scanners)

## Current Service Inventory
- `postgres`: relational datastore for scans and findings
- `redis`: job queue broker used by controller/workers
- Future additions (`minio`, `qdrant`, `frontend`, etc.) will be added alongside Compose assets.

## Manual Service Bring-up

### Postgres
```bash
docker run --rm -d \
  --name medusa-postgres \
  -e POSTGRES_DB=medusa \
  -e POSTGRES_USER=medusa \
  -e POSTGRES_PASSWORD=medusa \
  -p 5432:5432 \
  postgres:15
```

- Matches the controller default URL: `postgresql+psycopg2://medusa:medusa@localhost:5432/medusa`.
- Use `docker logs medusa-postgres` to confirm readiness before running migrations.

### Redis
```bash
docker run --rm -d \
  --name medusa-redis \
  -p 6379:6379 \
  redis:7
```

- Align worker queue keys with the controller default (`queues:nuclei:jobs`) until centralized config is delivered.

### Teardown
```bash
docker stop medusa-postgres medusa-redis
```

Compose files, `.env` templates, and data volumes under `infra/docker/` remain TODO. Track progress in the Phase 1 issues.

## Security Notes
- Restrict Docker to a trusted network segment; scanners should only access explicitly authorized targets.
- Rotate the default database password before exposing any services outside of localhost.
- Keep Docker Engine patched to the latest stable release prior to running external scans.
