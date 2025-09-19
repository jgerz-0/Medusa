# Automated Pentest & Binary Analysis Platform

Medusa is an **agentic AI-driven Cyber Reasoning System** that orchestrates reconnaissance, scanning, enrichment, and reporting workflows across web applications and binaries. Deterministic scanner output remains the source of truth, while AI enrichment layers add human-consumable context and prioritization.

## Core Capabilities
- **Agentic pipeline** – Recon → Scan → Validate → Enrich → Report with auditable hand-offs.
- **Multi-scanner coverage** – Nuclei, ZAP, SQLMap, AFL, angr, and static analyzers running inside isolated containers.
- **Deterministic CVE mapping** – NVD/CIRCL lookups with vector-store enrichment that never overrides scanner facts.
- **Security-first architecture** – Explicit scope enforcement, RBAC, and immutable job logs across all services.
- **Cloud-native execution** – Containerized workers with optional Kubernetes orchestration for horizontal scale.

## Phase 1 Focus (Foundations)
Phase 1 establishes the local development baseline that every later milestone builds upon.

| Deliverable | Description | Status |
| --- | --- | --- |
| Repository skeleton | Controller, worker, docs, and infrastructure directories with lint/test scaffolding. | ✅ Complete – directories and tooling land in `controller/`, `workers/`, `frontend/`, and `infra/`. |
| FastAPI controller | `/scan` endpoint validating scope and enqueueing jobs. | ✅ Complete – `controller/main.py` exposes authenticated CRUD + queue integration. |
| Docker Compose stack | Local environment booting Postgres, Redis, MinIO, Qdrant, the controller, nuclei worker, and frontend. | ✅ Complete – `infra/docker/docker-compose.yml` + `.env` defaults stand up the full stack with hot-reload mounts. |
| Redis + nuclei worker | Local Docker Compose wiring to execute proof-of-concept web scans. | ✅ Complete – worker container subscribes to shared queue defaults and reports back through authenticated callbacks. |
| Postgres schema | Minimum tables for scans, targets, findings, and audit log. | ✅ Complete – SQLAlchemy models now align with Alembic migrations (including finding metadata hashing and principal credentials). |
| Minimal Next.js UI | Read-only list of scans and findings surfaced from Postgres. | ⏳ Pending – current Next.js app is a landing page without data bindings. |

Progress on these items should be tracked through issues mapped to the roadmap phases in `ROADMAP.md`.

The Minimal Next.js UI now redirects the root route to `/scans`, exposes a `/scans` dashboard with manual nuclei launch controls, and provides a `/findings` view with filtering for severity, status, and scan context.

## Quickstart (Local Development)

### Prerequisites
- Docker Engine 20+ with Compose V2
- Optional: Python 3.11 with `poetry` (running unit tests or scripts outside containers)
- Optional: Node.js 20 with `pnpm` (frontend lint/unit tests outside containers)

### 1. Clone the repository
```bash
git clone https://github.com/<org>/medusa.git
cd medusa
```

### 2. Boot the local stack with Docker Compose
```bash
cd infra/docker
cp .env.example .env  # adjust secrets/ports as needed

docker compose up --build -d
docker compose ps
```

The compose file mounts `controller/`, `workers/web/nuclei/`, and `frontend/` into their respective containers so host edits trigger FastAPI reloads, worker hot-reloads, and Next.js hot module updates. Persistent data lives under `infra/docker/data/`.

### 3. Run migrations and validate the pipeline
```bash
# Apply Alembic migrations against the Postgres container
docker compose exec controller poetry run alembic upgrade head

# Optional: exercise the end-to-end nuclei flow
./infra/docker/smoke-test.sh
```

The smoke test seeds demo targets, enqueues a nuclei job, and waits for the worker callback. Set `COMPOSE_BIN=podman compose` if you prefer an alternate runtime.

### 4. Develop against the running services
- Controller API: http://localhost:8000 (OpenAPI at `/docs`)
- Analyst dashboard: http://localhost:3000 (HTTP basic auth using `analyst` / `analyst` unless you override `DASHBOARD_BASIC_*` in `.env`)
- MinIO console: http://localhost:9001
- Qdrant HTTP API: http://localhost:6333

Helpful commands:

```bash
# Tail controller logs with audit events
docker compose logs -f controller

# Inspect queued nuclei jobs
docker compose exec redis redis-cli llen queues:nuclei:jobs

# Tear everything down and wipe volumes
docker compose down -v
```

### 5. Run controller tests locally (optional)
```bash
poetry install
PYTHONPATH=. poetry run pytest controller/tests
PYTHONPATH=. poetry run python controller/scripts/check_migrations.py
```

These commands run entirely on the host using SQLite so you can iterate without touching the Compose stack. The migration check ensures SQLAlchemy models stay aligned with Alembic revisions.

### Analyst workflow: launching scans from the console

1. Register the asset under **Targets** in the controller and confirm its `is_authorized` flag is `true`.
2. Navigate to `http://localhost:3000/scans`, select the authorized target, and choose a scan profile preset.
3. Submit the form. The UI performs an optimistic update while the controller validates scope and enqueues the nuclei job. Any validation issues returned by the API are rendered inline for rapid remediation.

| Preset | Controller profile | Requested hosts | Primary use case |
| --- | --- | --- | --- |
| Baseline Web Recon | `web-baseline` | Derived from the selected target | Daily surface validation against hardened nuclei defaults. |
| API Deep Dive | `api-deep-dive` | `api.medusa.local` | Authenticated API sweeps with throttled rates. |
| External Attack Surface | `external-attack-surface` | `www.medusa.local`, `portal.medusa.local` | Weekly external perimeter checks targeting high-signal templates. |

Controller presets map directly to curated nuclei template bundles:

- `web-baseline` executes hardened configuration, panel, and DNS transfer checks (`phpinfo-detect`, `jenkins-login`, `dns-zone-transfer`).
- `api-deep-dive` layers in API documentation exposures to catch leaky Postman portals and Swagger consoles before authenticated sweeps.
- `external-attack-surface` extends the baseline with high-signal CVE probes and weak SSH cipher enumeration for weekly perimeter sweeps.

Status banners track optimistic queueing (`Queueing…`), success acknowledgements, and controller validation failures so analysts can move quickly without sacrificing auditability.

### Manage database migrations

The controller uses Alembic for deterministic schema changes. Common commands:

```bash
# generate a new migration after editing SQLAlchemy models
poetry run alembic revision --autogenerate -m "add_new_columns"

# apply the latest schema changes
poetry run alembic upgrade head

# verify that the database matches the models (used in CI)
PYTHONPATH=. poetry run python scripts/check_migrations.py
```

## Project Layout
```
.
├── controller/          # FastAPI service + DB migrations
├── workers/
│   ├── web/nuclei/      # Phase 1 nuclei worker
│   └── ...              # Additional scanners added in later phases
├── frontend/            # Next.js dashboard
├── docs/                # Architecture, ops, and contributor documentation
├── infra/
│   ├── docker/          # Compose overrides, local secrets templates
│   ├── helm/            # Kubernetes manifests (Phase 5+)
│   └── terraform/       # Cloud infrastructure definitions (Phase 5+)
└── tests/               # API, worker, and integration tests
```

## Security Posture Checklist
- All inbound targets validated against authorized scope lists.
- Jobs execute under least-privilege service accounts.
- Findings stored immutably with audit metadata (who/what/when).
- Secrets managed via `.env` templates locally and Kubernetes Secrets remotely.

## Additional Resources
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Roadmap & Milestones](ROADMAP.md)
- [Local Docker Guidance](docs/DOCKER.md)
- [Kubernetes Playbooks](docs/KUBERNETES.md)
- [Terraform Deployment](docs/TERRAFORM.md)
- [Contributing Guide](docs/CONTRIBUTING.md)

---
For questions on Phase 1 planning or implementation details, open a discussion or reach out to the engineering leads.
