# Binary Preprocessing Workflow

This document explains how analysts stage binary uploads for preprocessing,
how the controller enforces scope, and how the worker triages artifacts before
they enter heavier pipelines such as emulation or fuzzing.

## Overview

1. **Analyst upload** – Analysts push firmware images, executables, or other
   binary samples into the approved MinIO bucket (default: `binary-uploads`).
2. **Controller enqueue** – The analyst calls `POST /preprocess` with the
   MinIO bucket/key pair plus the target identifier. The controller validates
   the target scope, records an immutable audit event, creates a `Scan` row, and
   enqueues a job onto Redis (`queues:binary:preprocess`).
3. **Worker execution** – `workers/binary/preprocess` consumes jobs via Redis.
   The worker downloads the object from MinIO/S3, performs file-type detection
   with `python-magic`, evaluates triage policies (MIME allow-list, file size
   guardrails), writes normalized metadata into Postgres (`binary_samples`
   table), and persists the metadata JSON into MinIO for downstream agents.
4. **Downstream consumers** – Additional workers (emulation, fuzzing, CVE
   enrichment) read the normalized metadata and decide which follow-on actions
   are authorized.

The workflow is deterministic: scope validation happens in the controller, all
policy decisions are recorded with reasons, and audit logs are emitted for every
sensitive transition.

### Storage Layout

- **Upload bucket** – Operators provision a MinIO/S3 bucket (default:
  `binary-uploads`) where analysts drop raw samples. The controller job request
  references this bucket/key pair.
- **Metadata bucket/prefix** – The preprocess worker emits normalized JSON
  metadata under `binary-metadata/preprocess/metadata/` by default. Override the
  bucket via `BINARY_METADATA_BUCKET` and adjust the prefix with
  `BINARY_METADATA_PREFIX` to keep downstream agents scoped.

Both locations must exist before enqueuing jobs. The worker fails closed if the
metadata bucket or prefix is missing so artifacts never leak into implicit
paths.

## Controller Usage

`controller/main.py` exposes a new `POST /preprocess` endpoint. Required JSON
payload fields:

```json
{
  "target_id": "uuid-from-/targets",
  "object_bucket": "binary-uploads",
  "object_key": "uploads/firmware.bin",
  "file_name": "firmware.bin",
  "expected_scope": "prod.example.com",
  "metadata": {
    "sha256": "...",
    "notes": "field observations"
  }
}
```

* `target_id` must reference an authorized target.
* `expected_scope` is optional but recommended; if it does not match the stored
  target scope the controller raises `400` and records an audit event to surface
  potential tampering.
* `metadata` is forwarded verbatim to the worker under the
  `analyst_metadata` key so downstream agents retain analyst context.

Successful enqueue returns `202 Accepted` with the serialized `Scan` record.
The controller always records:

- A `Scan` row with `scanner="binary_preprocess"` and the MinIO location.
- An `AuditLog` entry when jobs are queued.
- An additional `AuditLog` entry if scope assertions fail.

## Worker Deployment

The worker is intentionally modular:

- `workers/binary/preprocess/app.py` – FastAPI health endpoint (`/healthz`) used
  by Kubernetes or Docker Compose liveness probes.
- `workers/binary/preprocess/worker.py` – CLI/long-running process that polls
  Redis, performs magic-based detection, enforces policies, writes metadata to
  Postgres, and persists JSON documents to MinIO.
- `workers/binary/preprocess/storage.py` – SQLAlchemy repository and S3 helper.
- `workers/binary/preprocess/policies.py` – MIME allow-list and max-size
  policies with deterministic decisions.

### Static Analysis Worker

Phase two introduces `workers/binary/static_analysis`, a companion worker that
consumes jobs from `queues:binary:static-analysis`, runs `checksec` and
`bandit` inside hardened container runtimes, and posts normalized findings back
to the controller. The worker is intentionally deterministic:

- CLI flags for the runtime are allow-listed (`--rm`, `--network=none`,
  `--cpus`, `--memory`, `--pids-limit`, `--security-opt`, `-v`). Any attempt to
  use disallowed flags raises an exception before the container launches.
- Each tool mounts the downloaded artifact read-only under `/workspace` inside
  the container. No user-supplied command line arguments are honored.
- Raw JSON output for each tool is persisted to MinIO using the
  `analysis/reports/<sample-id>/<tool>-<uuid>.json` convention via the shared
  `S3ObjectStorageClient` wrapper.
- Findings are normalized into the `binary_static_analysis_findings` table with
  immutable hashes, mirroring the guarantees of network scan findings.

Jobs are queued through the new controller endpoint:

```http
POST /binary/static-analysis
{
  "sample_id": "uuid-from-binary_samples",
  "target_id": "optional-guard",
  "metadata": {"profile": "baseline"}
}
```

The controller validates ownership of the binary sample, records an audit log,
creates a `Scan` row with `scanner="binary_static_analysis"`, and pushes a job
onto Redis. Workers call back to
`/internal/binary/static-analysis/callback` using the shared secret supplied in
`MEDUSA_BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN`.

### Fuzzing Worker

Phase three introduces the fuzzing worker located under
`workers/binary/fuzzing`. The worker consumes jobs from
`queues:binary:fuzzing`, executes hardened AFL and libFuzzer harnesses, and
streams crash evidence back to the controller. The harnesses are executed inside
pre-built container images so no untrusted arguments are injected at runtime.

- Jobs are queued via `POST /binary/fuzzing`. Operators must reference an
  existing normalized sample and can optionally supply a maximum fuzzing
  duration. The controller records an audit event, creates a
  `scanner="binary_fuzzing"` scan row, and enqueues onto Redis.
- Each fuzzer runs inside an isolated container with the sample mounted
  read-only at `/workspace/<artifact>`. Environment variables provide the sample
  path, scan identifier, and tool name to the harness.
- Harness stdout is expected to emit structured JSON. Crash metadata is
  normalized into `binary_fuzzing_findings` while raw stdout/stderr are persisted
  to MinIO using the `analysis/fuzzing/<sample-id>/<tool>-<uuid>.json` naming
  convention.
- The worker posts results to `/internal/binary/fuzzing/callback` with the
  shared secret stored in `MEDUSA_BINARY_FUZZING_CALLBACK_TOKEN`.

#### Fuzzing Environment Variables

| Variable | Purpose |
| --- | --- |
| `BINARY_FUZZING_QUEUE_KEY` | Redis list key for fuzzing jobs (default `queues:binary:fuzzing`). |
| `BINARY_FUZZING_DEAD_LETTER_KEY` | Redis key for failed fuzzing jobs. |
| `BINARY_FUZZING_RUNTIME` | Container runtime binary (`docker` or `podman`). |
| `BINARY_FUZZING_RUNTIME_FLAGS` | Space-separated runtime flags validated against the allow-list. |
| `BINARY_FUZZING_AFL_IMAGE` / `BINARY_FUZZING_LIBFUZZER_IMAGE` | Container images containing the hardened harnesses. |
| `BINARY_FUZZING_AFL_COMMAND` / `BINARY_FUZZING_LIBFUZZER_COMMAND` | Entry commands executed inside the containers. |
| `BINARY_FUZZING_ENABLE_AFL` / `BINARY_FUZZING_ENABLE_LIBFUZZER` | Toggle individual fuzzers (default enabled). |
| `BINARY_FUZZING_MAX_DURATION` | Default maximum runtime per fuzzer in seconds (default 900). |
| `BINARY_FUZZING_BUCKET` | Bucket for persisted fuzzing artifacts (defaults to the sample bucket). |
| `BINARY_FUZZING_PREFIX` | Prefix inside the artifact bucket (default `analysis/fuzzing/`). |
| `MEDUSA_BINARY_FUZZING_CALLBACK_TOKEN` | Shared secret required for fuzzing worker callbacks. |

Run the fuzzing worker locally:

```bash
poetry run python -m workers.binary.fuzzing.worker
```

Execute a single job for debugging:

```bash
poetry run python -m workers.binary.fuzzing.worker --once job.json
```

### Environment Variables

| Variable | Purpose |
| --- | --- |
| `BINARY_PREPROCESS_QUEUE_KEY` | Redis list key for jobs (default `queues:binary:preprocess`). |
| `BINARY_PREPROCESS_DEAD_LETTER_KEY` | Redis key for failed jobs. |
| `BINARY_PREPROCESS_ALLOWED_MIMES` | Comma-separated MIME allow-list. |
| `BINARY_PREPROCESS_MAX_BYTES` | Maximum allowed artifact size in bytes (default 50 MiB). |
| `BINARY_METADATA_BUCKET` | Bucket for normalized metadata JSON. Falls back to the artifact bucket. |
| `BINARY_METADATA_PREFIX` | Prefix inside the metadata bucket (default `preprocess/metadata/`). |
| `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | MinIO/S3 connectivity. |
| `DATABASE_URL` | SQLAlchemy URL for Postgres. |
| `BINARY_STATIC_ANALYSIS_QUEUE_KEY` | Redis list key for static analysis jobs (`queues:binary:static-analysis`). |
| `BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY` | Redis key for failed static analysis jobs. |
| `BINARY_STATIC_ANALYSIS_RUNTIME` | Container runtime binary (`docker` or `podman`). |
| `BINARY_STATIC_ANALYSIS_RUNTIME_FLAGS` | Space-separated runtime flags validated against the allow-list. |
| `BINARY_STATIC_ANALYSIS_CHECKSEC_IMAGE` | Container image that provides the `checksec` CLI. |
| `BINARY_STATIC_ANALYSIS_BANDIT_IMAGE` | Container image that provides the `bandit` CLI. |
| `BINARY_STATIC_ANALYSIS_TOOL_TIMEOUT` | Per-tool execution timeout in seconds (default 120). |
| `BINARY_ANALYSIS_BUCKET` | Bucket for persisted analyzer artifacts (defaults to the sample's bucket). |
| `BINARY_ANALYSIS_PREFIX` | Prefix inside the analysis bucket (default `analysis/reports/`). |
| `MEDUSA_BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN` | Shared secret required for worker callbacks. |

Run the worker locally:

```bash
poetry run python -m workers.binary.preprocess.worker
```

### Symbolic Execution Worker

Phase four introduces the angr symbolic execution worker under
`workers/binary/angr`. The worker consumes jobs from
`queues:binary:symbolic-execution`, downloads the preprocessed sample, launches a
hardened angr container, and posts normalized path exploration findings back to
the controller. Harnesses are locked behind allow-listed runtime flags to keep
execution deterministic and prevent privilege escalation.

- Jobs are queued via `POST /binary/symbolic-execution`. Analysts must reference
  a normalized sample and can optionally request a maximum depth or timeout. The
  controller records an audit entry, creates a
  `scanner="binary_symbolic_execution"` scan row, and enqueues onto Redis.
- The angr harness receives environment variables describing the artifact
  location, scan metadata, and optional analysis depth. Harness output is
  expected to be JSON containing `findings`, `artifacts`, and execution
  telemetry.
- Normalized findings persist into the
  `binary_symbolic_execution_findings` table with immutable evidence hashes while
  raw traces are stored in MinIO using the `analysis/symbolic/<sample-id>/...`
  naming convention.
- The worker posts results to
  `/internal/binary/symbolic-execution/callback` using the shared secret in
  `MEDUSA_BINARY_SYMBOLIC_EXECUTION_CALLBACK_TOKEN`.

#### Symbolic Execution Environment Variables

| Variable | Purpose |
| --- | --- |
| `BINARY_SYMBOLIC_EXECUTION_QUEUE_KEY` | Redis list key for symbolic execution jobs (default `queues:binary:symbolic-execution`). |
| `BINARY_SYMBOLIC_EXECUTION_DEAD_LETTER_KEY` | Redis key for failed symbolic execution jobs. |
| `BINARY_SYMBOLIC_EXECUTION_RUNTIME` | Container runtime binary (`docker` or `podman`). |
| `BINARY_SYMBOLIC_EXECUTION_RUNTIME_FLAGS` | Space-separated runtime flags validated against the allow-list. |
| `BINARY_SYMBOLIC_EXECUTION_IMAGE` | Container image delivering the hardened angr harness. |
| `BINARY_SYMBOLIC_EXECUTION_COMMAND` | Entry command executed inside the angr container. |
| `BINARY_SYMBOLIC_EXECUTION_TIMEOUT` | Default execution timeout in seconds (default 300). |
| `BINARY_SYMBOLIC_EXECUTION_BUCKET` | Bucket for persisted symbolic artifacts (defaults to the sample's bucket). |
| `BINARY_SYMBOLIC_EXECUTION_PREFIX` | Prefix inside the symbolic artifact bucket (default `analysis/symbolic/`). |
| `MEDUSA_BINARY_SYMBOLIC_EXECUTION_CALLBACK_TOKEN` | Shared secret required for symbolic execution worker callbacks. |

For single-job smoke tests:

```bash
poetry run python -m workers.binary.preprocess.worker --once
```

The worker logs policy outcomes and will dead-letter invalid payloads with a
JSON object describing the failure reason.

Launch the static analysis worker in a separate process:

```bash
poetry run python -m workers.binary.static_analysis.worker
```

Provide a JSON job file to exercise the smoke-test mode:

```bash
poetry run python -m workers.binary.static_analysis.worker --once job.json
```

## Data Model

`controller/db/models.py` now includes a `binary_samples` table storing:

- `scan_id` / `target_id`
- SHA-256 hash, MIME type, magic signature, and file size
- Policy status (`allowed` vs. `blocked`) and justification list
- Artifact storage location and normalized metadata hash
- Timestamps for forensic replay

SQLAlchemy events ensure payloads are normalized and hashed before persistence.

Static analysis results persist to `binary_static_analysis_findings`, linking
each tool finding back to the originating sample and scan with immutable JSON
hashes for evidence integrity.

## Testing

Two new pytest suites ensure deterministic behavior:

- `workers/binary/preprocess/tests/` verifies queue processing, policy
  enforcement, and metadata persistence.
- `workers/binary/fuzzing/tests/` exercises container orchestration, artifact
  persistence, and callback payload normalization.
- `controller/tests/test_api_contracts.py` exercises the `/preprocess` enqueue
  contract, validating scope mismatch auditing and Redis dispatch.

Run the tests with:

```bash
poetry run pytest workers/binary/preprocess/tests workers/binary/fuzzing/tests controller/tests/test_api_contracts.py
```

## Analyst Checklist

1. Upload artifact to MinIO bucket approved for the engagement.
2. Call `POST /preprocess` with the target, bucket/key, and optional scope
   assertion.
3. Monitor audit logs for `enqueue_binary_preprocess` actions or
   `preprocess_scope_mismatch` warnings.
4. Inspect normalized metadata in MinIO under `preprocess/metadata/` for
   triage outcomes before triggering heavier analysis pipelines.
