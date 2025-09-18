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
| Redis + nuclei worker | Local Docker Compose wiring to execute proof-of-concept web scans. | ⚠️ In progress – worker logic exists in `workers/web/nuclei/`, but Compose wiring and consistent queue/channel defaults remain TODO. |
| Postgres schema | Minimum tables for scans, targets, findings, and audit log. | ⚠️ In progress – Alembic migrations exist, yet models and migrations diverge and need reconciliation before end-to-end runs. |
| Minimal Next.js UI | Read-only list of scans and findings surfaced from Postgres. | ⏳ Pending – current Next.js app is a landing page without data bindings. |

Progress on these items should be tracked through issues mapped to the roadmap phases in `ROADMAP.md`.

## Quickstart (Local Development)

### Prerequisites
- Docker 20+ (used for one-off containers until Compose manifests land)
- Python 3.11 with `poetry`
- Node.js 20 with `pnpm`

### 1. Clone the repository
```bash
git clone https://github.com/<org>/medusa.git
cd medusa
```

### 2. Start backing services manually
Compose files are not yet published. Stand up Postgres and Redis explicitly before booting any services:

```bash
# Postgres (matches controller defaults)
docker run --rm -d \
  --name medusa-postgres \
  -e POSTGRES_DB=medusa \
  -e POSTGRES_USER=medusa \
  -e POSTGRES_PASSWORD=medusa \
  -p 5432:5432 \
  postgres:15

# Redis queue broker
docker run --rm -d \
  --name medusa-redis \
  -p 6379:6379 \
  redis:7
```

Reference the interim service notes in [docs/DOCKER.md](docs/DOCKER.md#manual-service-bring-up) for environment hardening guidance.

### 3. Run the FastAPI controller
```bash
cd controller
poetry install

# Required auth configuration
export MEDUSA_JWT_SECRET="dev-local-secret"
export MEDUSA_API_KEYS='["local-dev-key"]'

# Apply database schema (current migration set is still being reconciled with the models)
poetry run alembic upgrade head

# Launch the API
poetry run uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

With the API online you can exercise endpoints via the static API key, e.g.:

```bash
curl -X POST http://localhost:8000/targets \
  -H "Content-Type: application/json" \
  -H "X-API-Key: local-dev-key" \
  -d '{
    "name": "Example", 
    "url": "https://example.com", 
    "scope": {"allowed_hosts": ["example.com"]}
  }'
```

### 4. Start the nuclei worker (optional skeleton)
The worker can be exercised locally, but Redis channel names must be aligned manually until shared configuration lands:

```bash
cd ../workers/web/nuclei
poetry install
export REDIS_URL="redis://localhost:6379/0"
export NUCLEI_QUEUE_KEY="queues:nuclei:jobs"  # matches controller default
poetry run python worker.py
```

### 5. Frontend operations console
The Next.js dashboard now pulls live data from the controller and can orchestrate scoped scans. To run it locally:

```bash
cd frontend
pnpm install

# Point the UI at the locally running controller and provide credentials.
export CONTROLLER_API_BASE_URL="http://127.0.0.1:8000"
export CONTROLLER_API_KEY="local-dev-key"

pnpm dev
```

The `/scans` route now exposes a launch form that submits through a server action so controller secrets never reach the browser. Analysts can queue nuclei jobs directly from the console using the documented presets below.

### Analyst workflow: launching scans from the console

1. Register the asset under **Targets** in the controller and confirm its `is_authorized` flag is `true`.
2. Navigate to `http://localhost:3000/scans`, select the authorized target, and choose a scan profile preset.
3. Submit the form. The UI performs an optimistic update while the controller validates scope and enqueues the nuclei job. Any validation issues returned by the API are rendered inline for rapid remediation.

| Preset | Controller profile | Requested hosts | Primary use case |
| --- | --- | --- | --- |
| Baseline Web Recon | `web-baseline` | Derived from the selected target | Daily surface validation against hardened nuclei defaults. |
| API Deep Dive | `api-deep-dive` | `api.medusa.local` | Authenticated API sweeps with throttled rates. |
| External Attack Surface | `external-attack-surface` | `www.medusa.local`, `portal.medusa.local` | Weekly external perimeter checks targeting high-signal templates. |

Status banners track optimistic queueing (`Queueing…`), success acknowledgements, and controller validation failures so analysts can move quickly without sacrificing auditability.

### Manage database migrations

The controller uses Alembic for deterministic schema changes. Common commands:

```bash
# generate a new migration after editing SQLAlchemy models
poetry run alembic revision --autogenerate -m "add_new_columns"

# apply the latest schema changes
poetry run alembic upgrade head

# verify that the database matches the models (used in CI)
poetry run python scripts/check_migrations.py
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
