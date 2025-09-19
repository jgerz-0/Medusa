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

Run the worker locally:

```bash
poetry run python -m workers.binary.preprocess.worker
```

For single-job smoke tests:

```bash
poetry run python -m workers.binary.preprocess.worker --once
```

The worker logs policy outcomes and will dead-letter invalid payloads with a
JSON object describing the failure reason.

## Data Model

`controller/db/models.py` now includes a `binary_samples` table storing:

- `scan_id` / `target_id`
- SHA-256 hash, MIME type, magic signature, and file size
- Policy status (`allowed` vs. `blocked`) and justification list
- Artifact storage location and normalized metadata hash
- Timestamps for forensic replay

SQLAlchemy events ensure payloads are normalized and hashed before persistence.

## Testing

Two new pytest suites ensure deterministic behavior:

- `workers/binary/preprocess/tests/` verifies queue processing, policy
  enforcement, and metadata persistence.
- `controller/tests/test_api_contracts.py` exercises the `/preprocess` enqueue
  contract, validating scope mismatch auditing and Redis dispatch.

Run the tests with:

```bash
poetry run pytest workers/binary/preprocess/tests controller/tests/test_api_contracts.py
```

## Analyst Checklist

1. Upload artifact to MinIO bucket approved for the engagement.
2. Call `POST /preprocess` with the target, bucket/key, and optional scope
   assertion.
3. Monitor audit logs for `enqueue_binary_preprocess` actions or
   `preprocess_scope_mismatch` warnings.
4. Inspect normalized metadata in MinIO under `preprocess/metadata/` for
   triage outcomes before triggering heavier analysis pipelines.
