# Docker Setup

## Requirements
- Docker 20+
- Docker Compose

## Services
- `controller`: FastAPI app
- `redis`: queue broker
- `postgres`: database
- `minio`: artifact store
- `qdrant`: vector store

## Build
```bash
docker build -t pentest-controller ./controller
docker build -t pentest-nuclei ./workers/web/nuclei
