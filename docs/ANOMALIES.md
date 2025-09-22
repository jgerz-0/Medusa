# Anomaly Event Review

Medusa ingests anomaly signals from worker callbacks to highlight suspicious behavior (brute force, traffic spikes, and other detections). This workflow keeps metadata deterministic, RBAC scoped, and fully audited.

## API Endpoints

| Endpoint | Method | Description | RBAC |
| --- | --- | --- | --- |
| `/anomalies` | `GET` | Lists anomaly events with optional filters (`type`, `actor`, `source`, `from`, `to`) and pagination (`limit`, `offset`). | `findings:read` or `analyst` |
| `/anomalies/{id}` | `GET` | Returns a single anomaly event with sanitized metadata. | `findings:read` or `analyst` |
| `/internal/anomalies` | `POST` | Worker callback used to persist anomaly payloads. | Shared secret token |

### Filtering & Pagination

* `type` maps to `anomaly_type` in the database and enforces exact matches.
* `from` / `to` filter by `detected_at` timestamps (UTC, ISO-8601).
* Pagination is exposed via `limit`/`offset`; the UI maps page controls to these fields.
* Results are ordered by `detected_at` descending to surface the most recent signals first.

### Sanitized Metadata

Anomaly metadata can include third-party payloads. The controller serializes responses with:

* Recursive sanitization that converts complex objects to strings, base64-encodes bytes, and HTML-escapes text to prevent script injection.
* Depth and list guards (`5` levels, `50` items) plus string truncation to keep payloads reviewable.
* Audit logs capturing the filters, result counts, and target anomaly ID each time an analyst views data.

## Audit & Security Controls

* Every list/detail request writes an `AuditLog` record (`list_anomalies`, `view_anomaly`) with actor, resource identifiers, and applied filters.
* RBAC enforcement mirrors findings access: admins inherit access, analysts/read-only users require `findings:read` or `analyst`.
* Metadata snapshots are never mutated in-place; the serializer copies payloads before sanitization to keep the database authoritative.

## Frontend Workflow

The Next.js route `/anomalies` displays:

* **Anomaly Table** – sortable list of anomaly events with actor, source, frequency, and a preview of sanitized metadata. Pagination is consistent with the findings view.
* **Timeline Card** – chronological context for recent anomalies (latest 20 by default) with actor/source roll-ups for quick triage.
* **Role Notice** – highlights required roles so operations teams understand why access might be denied.

Filters are surfaced via URL parameters and summarized in the UI to simplify hand-offs between analysts.

## Operational Notes

* Extend anomaly ingestion by emitting structured payloads from new workers; the controller automatically sanitizes unknown fields.
* Integrations should continue to rely on deterministic callbacks—AI enrichment can annotate metadata but cannot override recorded values.
* When exporting or correlating anomalies, always reference the audit trail to prove who accessed sensitive telemetry.
