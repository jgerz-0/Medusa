# Finding Schema

The Medusa controller normalizes all scanner and validator output into a
single JSON schema. This allows the frontend, enrichment agents, and reporting
pipelines to reason about findings without vendor-specific adapters.

## Top-Level Fields

| Field | Type | Description |
| --- | --- | --- |
| `id` | `string` | UUID for the finding. |
| `scan_id` | `string` | UUID of the originating scan. |
| `title` | `string` | Human-readable title summarizing the issue. |
| `severity` | `string` | One of `critical`, `high`, `medium`, `low`, or `info`. |
| `cvss` | `number` | Deterministic CVSS approximation derived from severity. |
| `description` | `string` | Detailed description of the impact and context. |
| `cve_id` | `string` | Optional CVE identifier when applicable. |
| `detected_at` | `string` (ISO-8601) | Timestamp when the finding was first recorded. |
| `updated_at` | `string` (ISO-8601) | Timestamp of the most recent mutation. |
| `status` | `string` | Workflow status (`open`, `acknowledged`, `resolved`). |
| `validation_status` | `string` | Validator lifecycle state (`pending`, `queued`, `running`, `passed`, `failed`). |
| `validated_at` | `string` (ISO-8601, nullable) | Timestamp of the last successful validation. |
| `metadata` | `object` | Scanner-specific metadata preserved for audit. |
| `evidence` | `string` | JSON evidence serialized as a deterministic string. |
| `scanner` | `string` | Logical scanner/agent responsible for the finding. |
| `category` | `string` | One of `web`, `binary_static`, or `binary_fuzzing`. |
| `tool` | `string` | Specific tool or rule that generated the finding. |
| `enrichments` | `array<object>` | Attached enrichment payloads with provenance metadata. |
| `validations` | `array<object>` | Historical validator results (job id, validator, executed_at, notes). |
| `tags` | `array<string>` | Analyst-supplied tags for triage workflows. |
| `assigned_to` | `string` | Optional analyst assignment. |
| `tickets` | `array<object>` | External ticket metadata for downstream systems. |

## Severity Scoring

Severity strings map to deterministic CVSS approximations used by the reporting
pipeline and notification hooks:

| Severity | CVSS |
| --- | --- |
| `critical` | 9.5 |
| `high` | 8.0 |
| `medium` | 6.0 |
| `low` | 3.0 |
| `info` | 0.0 |

Validator and notification logic rely on this mapping—critical findings that
validate successfully trigger Slack and email alerts when configured.

## Validation History Objects

Entries inside the `validations` array include the following keys:

- `id` – UUID of the validation record.
- `job_id` – Identifier of the validator job that produced the result.
- `status` – `passed` or `failed`.
- `validator` – Human-readable identifier for the validator agent.
- `executed_at` – ISO-8601 timestamp when the retest completed.
- `requested_by` / `requested_at` – Principal and timestamp that queued the job.
- `notes` – Optional notes supplied by the validator.
- `metadata` / `evidence` – JSON payloads mirroring the worker callback.

## Callback Contracts

Validator workers must POST results to `/internal/validator/callback` using the
shared callback token. The payload mirrors the schema above and must include:

```json
{
  "job_id": "job-uuid",
  "finding_id": "finding-uuid",
  "status": "passed",
  "validator": "validator-worker",
  "executed_at": "2024-04-01T12:00:00Z",
  "metadata": {"notes": "secondary check"},
  "evidence": {"status": 200}
}
```

Critical findings transition to `validation_status=passed` only after a valid
callback, at which point notification hooks are invoked.
