# Automated Pentest & Binary Analysis Platform

Medusa is an **agentic AI-driven Cyber Reasoning System** that orchestrates reconnaissance, scanning, enrichment, and reporting workflows across web applications and binaries. Deterministic scanner output remains the source of truth, while AI enrichment layers add human-consumable context and prioritization.

## Core Capabilities
- **Agentic pipeline** – Recon → Scan → Validate → Enrich → Report with auditable hand-offs.
- **Multi-scanner coverage** – Nuclei, ZAP, SQLMap, AFL/libFuzzer fuzzing, checksec/bandit static analyzers, and angr symbolic execution harnesses running inside isolated containers.
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
| Minimal Next.js UI | Read-only list of scans and findings surfaced from Postgres. | ✅ Complete – `/scans` and `/findings` views read from Postgres with authenticated filters. |

Progress on these items should be tracked through issues mapped to the roadmap phases in `ROADMAP.md`.

## Phase 5 Highlights: Kubernetes & Terraform Automation

Phase 5 delivers the production-grade automation needed to run Medusa inside hardened Kubernetes clusters:

- **Helm safeguards** enforce Pod Security Standards, network policies, and optional metrics add-ons in the [Kubernetes Deployment Guide](docs/KUBERNETES.md).
- **Terraform modules** provision EKS, RDS, and S3 foundations with opinionated defaults captured in [Terraform Infrastructure](docs/TERRAFORM.md).
- **External Secrets integration** lets clusters pull credentials from AWS Secrets Manager via the `external-secrets` module and Helm toggles documented in both the [Terraform](docs/TERRAFORM.md#external-secrets-operator) and [Kubernetes](docs/KUBERNETES.md#deploy-external-secrets-optional) guides.
- **IRSA and ALB wiring** is automated through Terraform-managed IAM roles and the AWS Load Balancer Controller rollout covered in [docs/KUBERNETES.md](docs/KUBERNETES.md#provision-the-aws-load-balancer-controller).
- **Observability options** span embedded Prometheus/Grafana stacks and full Prometheus Operator installs as outlined in [docs/TERRAFORM.md](docs/TERRAFORM.md#observability) and the optional metrics stack configuration in [docs/KUBERNETES.md](docs/KUBERNETES.md#metrics-stack-optional).

## Operational Runbooks
- **[Disaster Recovery](docs/runbooks/DISASTER_RECOVERY.md)** – Documents RPO/RTO targets, RDS and S3/MinIO restoration workflows, cross-region failover via `infra/terraform` modules, validation commands wired into CI, and quarterly tabletop exercise checklists.

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

The compose file mounts `controller/`, `workers/web/nuclei/`, `workers/binary/preprocess/`, `workers/binary/fuzzing/`, and `frontend/` into their respective containers so host edits trigger FastAPI reloads, worker hot-reloads, and Next.js hot module updates. Persistent data lives under `infra/docker/data/`.

### 3. Prepare object storage, run migrations, and validate the pipeline
```bash
# Provision the MinIO buckets used by binary uploads and symbolic execution artifacts
docker compose exec minio mc alias set local http://localhost:9000 ${MINIO_ROOT_USER:-medusaadmin} ${MINIO_ROOT_PASSWORD:-medusaadmin123}
docker compose exec minio mc mb -p local/binary-uploads || true
docker compose exec minio mc mb -p local/analysis || true

# Apply Alembic migrations against the Postgres container
docker compose exec controller poetry run alembic upgrade head

# Optional: exercise the end-to-end nuclei flow
./infra/docker/smoke-test.sh
```

The smoke test seeds demo targets, enqueues a nuclei job, and waits for the worker callback. With the buckets in place, you can immediately enqueue binary preprocess, fuzzing, or symbolic execution jobs. Set `COMPOSE_BIN=podman compose` if you prefer an alternate runtime.

### 4. Develop against the running services
- Controller API: http://localhost:8000 (OpenAPI at `/docs`)
- Analyst dashboard: http://localhost:3000 (HTTP basic auth using `analyst` / `analyst` unless you override `DASHBOARD_BASIC_*` in `.env`)
- MinIO console: http://localhost:9001
- Qdrant HTTP API: http://localhost:6333

Helpful commands:

```bash
# Tail controller logs with audit events
docker compose logs -f controller

# Inspect symbolic execution retries and callbacks
docker compose logs -f binary-symbolic-worker

# Inspect queued nuclei jobs
docker compose exec redis redis-cli llen queues:nuclei:jobs

# Inspect queued symbolic execution jobs
docker compose exec redis redis-cli llen queues:binary:symbolic-execution

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

### Automate cluster deployments

Graduate from Docker Compose by applying the Terraform workflow in [docs/TERRAFORM.md](docs/TERRAFORM.md) and then the Helm playbooks in [docs/KUBERNETES.md](docs/KUBERNETES.md) to stand up the EKS cluster, External Secrets, and ALB ingress end-to-end.

```bash
cd infra/terraform/envs/dev

# Inspect and update terraform.tfvars with environment-specific values.
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Terraform modules provision EKS, RDS, S3, External Secrets, observability, and the Medusa Helm release. Helm values and secret delivery can be tailored per environment by editing the corresponding `envs/<env>/terraform.tfvars` file before running the plan.

### Analyst workflow: launching scans from the console

#### Register new targets via the API

Analysts (or automation) must register assets with `POST /targets` before the UI can launch scans. The endpoint enforces the `targets:write` RBAC role (admins inherit it); review the expanded policy matrix in [docs/RBAC.md](docs/RBAC.md).

Required JSON fields:

- `name` – Friendly display name for the asset.
- `scope` – Canonical hostname, scheme-qualified URL, or CIDR block that defines the authorized scope.
- `is_authorized` – Optional boolean that defaults to `true`; set to `false` if legal approval is still pending.

```bash
curl -X POST "http://localhost:8000/targets" \
  -H "Authorization: Bearer ${MEDUSA_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "Medusa Demo Web",
        "scope": "https://demo.medusa.internal",
        "is_authorized": true
      }'
```

For local demos you can seed the same records with `poetry run python controller/scripts/seed_targets.py`, which calls `POST /targets` equivalents against the database models. Teams building automation should pair the above flow with the generated OpenAPI reference at `http://localhost:8000/docs` to discover additional fields and error codes.

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
