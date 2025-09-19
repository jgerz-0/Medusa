# Validation Agent Interface

The validator agent performs targeted retests on findings before they are
promoted to consumers. All communication between the controller and the worker
uses deterministic JSON payloads to preserve auditability.

## Queue Job Payload

Jobs are enqueued on the `MEDUSA_VALIDATOR_QUEUE_CHANNEL` Redis list. Each item
is a JSON object with the following shape:

| Field            | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `job_id`         | string | ✅ | Unique identifier for this validation job. |
| `validation_id`  | string | ✅ | Identifier of the validation record persisted by the controller. |
| `finding_id`     | string | ✅ | Identifier of the finding under test. |
| `scan_id`        | string | ✅ | Identifier of the originating scan. |
| `target_id`      | string | ❌ | Target identifier associated with the finding. |
| `target`         | string | ❌ | Human readable scope (URL/hostname) for context. |
| `severity`       | string | ✅ | Normalised severity (`critical`/`high`/`medium`/`low`/`info`). |
| `validator`      | string | ✅ | Validator type to execute (currently `http` or `noop`). |
| `probe`          | object | ✅ | Validator specific configuration (see below). |
| `callback_url`   | string | ✅ | Controller endpoint that accepts the callback. |
| `attempts`       | number | ❌ | Retry counter maintained by the worker. |
| `metadata`       | object | ❌ | Additional context captured by the controller. |

### HTTP Probe

When `validator` is `http` the `probe` object supports the following keys:

- `url` (string, required): Absolute URL to request during validation.
- `method` (string, optional): HTTP method, default `GET`.
- `expected_status` (number, optional): Response code required for confirmation.
- `match` (string, optional): Substring that must appear in the response body.
- `timeout_seconds` (number, optional): Request timeout, defaults to worker
  configuration.

### Noop Probe

When a deterministic retest cannot be derived, the controller will issue a
`noop` probe. The worker records the attempt but does not perform any network
operations, returning an `inconclusive` outcome.

## Callback Payload

Workers must POST the following JSON body to
`/internal/validate/callback` with the `X-Callback-Token` header populated using
`MEDUSA_VALIDATOR_CALLBACK_TOKEN`:

| Field            | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `validation_id`  | string | ✅ | Validation record identifier. |
| `finding_id`     | string | ✅ | Finding identifier. |
| `job_id`         | string | ✅ | Job identifier provided by the controller. |
| `status`         | string | ✅ | `queued`, `running`, `completed`, or `failed`. |
| `processed_at`   | string | ✅ | ISO8601 timestamp of completion. |
| `outcome`        | string | ❌ | `confirmed`, `not_reproduced`, or `inconclusive` (required when `status`=`completed`). |
| `attempts`       | number | ❌ | Retry counter reported by the worker. |
| `observations`   | object | ❌ | Deterministic telemetry collected during validation. |
| `evidence`       | object | ❌ | Evidence snippet or structured output captured during the probe. |
| `error`          | string | ❌ | Human readable error message when validation fails. |

Callback payloads are immutable once persisted. The controller augments the
associated finding with a `validation` summary that captures the latest status,
outcome, and supporting telemetry for analysts.
