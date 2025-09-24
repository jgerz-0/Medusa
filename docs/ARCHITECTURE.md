# Architecture Overview

Medusa embraces agentic modularity. Each service is responsible for a bounded function, communicates over deterministic JSON interfaces, and operates under least privilege.

## High-Level Diagram
```
┌──────────┐      ┌────────┐      ┌───────────┐      ┌────────────┐
│  Client  │ ---> │Controller│ --> │ Work Queue│ --> │ Scanner Jobs│
└──────────┘      └────────┘      └───────────┘      └─────┬──────┘
                                                             │
                                              ┌──────────────┴──────────────┐
                                              │            Agents           │
                                              │ Recon · Enrich · Validate   │
                                              └──────────────┬──────────────┘
                                                             │
                                       ┌──────────────┐   ┌─────────────┐
                                       │   Postgres   │   │   MinIO     │
                                       │ (Findings)   │   │ (Artifacts) │
                                       └──────────────┘   └─────────────┘
```

## Components
- **Controller (FastAPI)**
  - Validates incoming scan requests and target scope.
  - Persists scan definitions and issues JWT-scoped job tokens.
  - Emits audit events for every state transition.
- **Queue (Redis)**
  - The controller `RPUSH`es jobs into Redis lists named `queues:<agent>:jobs` and workers compete on `BLPOP`, ensuring a single agent claims each payload while keeping operations transparent via `redis-cli`.
  - Failed jobs are retried in-line: workers increment the embedded `attempts` counter and `RPUSH` back to the same list until `max_retries` is hit, then move the payload (with error context) to `queues:<agent>:dead` for manual remediation.
  - Operators should pin queue channel environment variables (`MEDUSA_*_QUEUE_CHANNEL`, `<worker>_QUEUE_KEY`) to the agreed namespace, monitor the corresponding `:dead` keys, and tune `REDIS_URL` options (TLS, timeouts, connection pooling) per environment because Redis is the sole supported transport today; RabbitMQ support is not yet scheduled on the roadmap.
- **Workers**
  - Containerized wrappers around scanners (nuclei, ZAP, SQLMap, AFL/libFuzzer fuzzing, checksec, bandit).
  - Normalize output into the shared JSON Finding schema.
  - Upload heavy artifacts (pcaps, binaries, logs) to MinIO.
  - **CVE Enrichment Worker** – fetches deterministic advisories from NVD and CIRCL, emits structured metadata for findings, and writes normalized advisory embeddings to Qdrant for semantic enrichment without blocking Redis callbacks.

### Anomaly Detection Worker

- Polls the controller's immutable `audit_log` table for suspicious sequences (excessive access denials, sustained rate limits, repeated scope mismatches) and posts them to `POST /internal/anomalies`.
- Authenticates with the controller via the `X-Callback-Token` header. The shared secret is configured through `ANOMALY_CALLBACK_TOKEN` (and mirrored as `MEDUSA_ANOMALY_CALLBACK_TOKEN` for the controller).
- Runtime tunables are exposed through environment variables so operators can harden detections without editing code:
  - `ANOMALY_POLL_INTERVAL` (seconds) – cadence for scanning the audit log.
  - `ANOMALY_BATCH_SIZE` – maximum number of audit rows read per poll.
  - `ANOMALY_STATE_KEY` – Redis key used to persist the last processed timestamp for crash-safe recovery.
  - `ANOMALY_CALLBACK_URL` – defaults to the controller's internal service DNS entry.
  - `ANOMALY_HTTP_TIMEOUT` – fail-fast bound for callback delivery.
  - `ANOMALY_SOURCE` – identifier persisted with anomaly events for attribution.
  - Threshold knobs for each heuristic:
    - `ANOMALY_ACCESS_DENIED_THRESHOLD` and `ANOMALY_ACCESS_DENIED_WINDOW_SECONDS`.
    - `ANOMALY_RATE_LIMIT_THRESHOLD` and `ANOMALY_RATE_LIMIT_WINDOW_SECONDS`.
    - `ANOMALY_SCOPE_MISMATCH_THRESHOLD` and `ANOMALY_SCOPE_MISMATCH_WINDOW_SECONDS`.
    - `ANOMALY_DETECTOR_COOLDOWN_SECONDS` – suppresses duplicate alerts across poll cycles.
- See [`workers/anomaly/README.md`](../workers/anomaly/README.md) for operator-focused configuration guidance.
- Requires the same `DATABASE_URL` and `REDIS_URL` secrets as the controller so heuristics observe the canonical audit stream and share state atomically.
- **Agents**
  - **Recon Agent** – Discovers assets from authorized inventory feeds.
  - **Preprocess Agent** – Classifies binaries, extracts metadata, enforces triage rules.
  - **Enrichment Agent** – Calls NVD/CIRCL, consults Qdrant for semantic matches, annotates findings without mutating raw evidence.
  - **Validator Agent** – Executes targeted retests before critical findings are published.
  - **Reporter Agent** – Consolidates output, publishes to Postgres, triggers notifications.
- **Storage**
  - **Postgres** – Canonical store for scans, targets, findings, audit logs, API keys.
  - **MinIO/S3** – Evidence blobs, fuzzing crashes, reports.
  - **Qdrant** – Vector embeddings for advisories and scanner fingerprints.
- **Frontend (Next.js)**
  - Analyst dashboard for scan orchestration, findings triage, and audit review.

## Data Flow (Phase 1 Baseline)
1. Analyst requests a scan via UI/CLI.
2. Controller authenticates the user, validates scope, and enqueues a nuclei job.
3. Worker pulls the job, executes the scanner within an ephemeral container, and posts results back through the controller callback API.
4. Findings persist to Postgres; artifacts (scan logs, templates) land in MinIO.
5. UI polls `/scans` and `/findings` to display state transitions.

### Phase 2 Enrichment Extension
1. Analyst (or automation) calls `/enrich` with a finding identifier and optional advisory sources.
2. The controller enqueues a CVE enrichment job on `queues:enrichment:cve` and records an audit event.
3. The CVE worker fetches NVD + CIRCL advisories with pinned user-agent headers, normalizes the payload, and prepares metadata for controller ingestion. Deterministic embeddings are generated from the same payload and persisted to Qdrant for later semantic lookups.
4. The enriched metadata attaches to the original finding without mutating stored evidence, enabling deterministic provenance for remediation guidance while keeping advisory embeddings auditable.

## Security Controls
- All inter-service communication authenticated with mTLS (planned) or signed JWTs (Phase 1).
- Network policies restrict scanner pods to egress only to approved target CIDRs.
- Secrets sourced from Vault/External Secrets in Kubernetes; `.env.example` governs local development.
- Audit log appended on every scan lifecycle event (created, queued, running, completed, rejected).
- Role-based access control enforces least privilege. Admins manage credentials and audit logs;
  analysts operate scans, view findings, and enqueue enrichment but cannot touch `/principals`.
- API keys are never stored in clear text. The controller hashes incoming keys with `_hash_secret`
  and persists only the hash and a truncated `key_fingerprint` for rotation tracking.
- Every rejected authentication or authorization attempt emits an `access_denied` audit entry with
  the attempted resource, required roles, and rotation fingerprint to aid incident response.
- Revocation returns `401` with `"API key revoked"` and the same fingerprint metadata, ensuring
  operators can correlate secrets without revealing them.

## Resilience & Disaster Recovery
- RPO/RTO objectives, Terraform-driven restoration steps for RDS/S3, and cross-region failover workflows are cataloged in the [Disaster Recovery Runbook](runbooks/DISASTER_RECOVERY.md). Follow its validation commands and tabletop cadence to keep architecture assumptions verified.

## Extensibility Principles
- New agents register their JSON schema in `docs/interfaces/` and implement handshake contracts with the controller.
- Infrastructure definitions (Docker, Helm, Terraform) remain declarative and version controlled.
- LLM usage limited to summarization/enrichment; deterministic scanner evidence cannot be overridden or deleted.
