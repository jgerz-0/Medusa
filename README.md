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

| Deliverable | Description |
| --- | --- |
| Repository skeleton | Controller, worker, docs, and infrastructure directories with lint/test scaffolding. |
| FastAPI controller | `/scan` endpoint validating scope and enqueueing jobs. |
| Redis + nuclei worker | Local Docker Compose wiring to execute proof-of-concept web scans. |
| Postgres schema | Minimum tables for scans, targets, findings, and audit log. |
| Minimal Next.js UI | Read-only list of scans and findings surfaced from Postgres. |

Progress on these items should be tracked through issues mapped to the roadmap phases in `ROADMAP.md`.

## Quickstart (Local Development)

### Prerequisites
- Docker 20+ and Docker Compose
- Python 3.11 with `poetry`
- Node.js 20 with `pnpm`

### Bootstrap the stack
```bash
# clone and enter the repository
git clone https://github.com/<org>/medusa.git
cd medusa

# launch shared services (Postgres, Redis, MinIO, Qdrant)
docker compose up -d

# install controller dependencies and run API (FastAPI + uvicorn)
cd controller
poetry install
poetry run uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Start the nuclei worker
In a separate shell:
```bash
cd workers/web/nuclei
poetry install
poetry run python worker.py
```

### Seed sample data & launch UI
```bash
# apply migrations and seed example scope data
cd controller
poetry run alembic upgrade head
poetry run python scripts/seed_targets.py

# start the Next.js dashboard
cd ../frontend
pnpm install
pnpm dev --host
```

Once the UI is running, navigate to `http://localhost:3000` to queue scans and inspect findings.

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
