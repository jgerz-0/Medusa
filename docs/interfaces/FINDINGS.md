# Finding JSON Schema

Medusa exposes a consolidated finding schema across the controller, workers, and
frontend. This document describes the deterministic fields, severity scoring,
and validation lifecycle now enforced in Phase 4.

## Top-Level Fields

Each finding returned by the controller adheres to the following structure:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `id` | string | Stable identifier for the finding record. |
| `scan_id` | string | Identifier of the originating scan. |
| `title` | string | Human readable summary of the issue. |
| `severity` | string | Normalized severity: `critical`, `high`, `medium`, `low`, or `info`. |
| `severity_score` | integer | Deterministic score derived from severity (`critical`=100, `high`=75, `medium`=50, `low`=25, `info`=0). |
| `description` | string | Detailed description of the finding. |
| `status` | string | One of `pending_validation`, `open`, or `invalidated`. |
| `metadata` | object | Scanner specific metadata plus normalization metadata (`scanner`, `tool`, `template_id`, `validation`, etc.). |
| `evidence` | string | JSON string representation of the immutable evidence payload. |
| `enrichments` | array | Enrichment records returned from the CVE enrichment pipeline. |
| `category` | string | `web`, `binary_static`, or `binary_fuzzing`. |

Evidence remains stored as structured JSON in the database. The API surfaces a
stringified version to simplify frontend display while preserving immutability
via the evidence hash.

## Severity Normalization

The controller and workers now share a single severity normalization helper.
Allowed values are:

- `critical`
- `high`
- `medium`
- `low`
- `info`

Any worker callback that emits an unsupported severity is rejected. The
`severity_score` field is included in the `metadata` block to provide a
consistent numeric representation for sorting and reporting.

## Validation Lifecycle

Web findings transition through a validation lifecycle managed by the new
validator agent:

1. **`pending_validation`** – Initial state after a worker callback. The
   controller queues a validator job and records the job identifier and
   scheduled timestamp in `metadata.validation`.
2. **`open`** – Set when the validator confirms the finding. The
   `validation_status` becomes `passed`, and `validated_at` records the time of
   the successful retest.
3. **`invalidated`** – Set when the validator cannot reproduce the issue. The
   `validation_status` becomes `failed`, and the controller preserves the
   validator's diagnostic details.

Binary static analysis and fuzzing findings are considered deterministic and are
returned as `open` with a synthetic validation block referencing the execution
timestamp.

## Notifications

When a `critical` finding transitions to `open`, the controller emits
notifications through the configured Slack webhook and/or SMTP settings. The
notification payload contains:

- Finding identifier and title
- Target scope and scanner
- Validation status and timestamp
- Evidence hash and contextual metadata (scan ID, validator job ID)

Notifications are gated by the validator outcome to ensure analysts only receive
alerts for reproducible, validated issues.
