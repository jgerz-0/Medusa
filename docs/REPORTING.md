# Reporting & Workflow Enhancements

Phase 6 extends the Medusa controller and dashboard with analyst workflows, export pipelines, and ticketing hooks. These features remain deterministic and auditable while giving analysts richer tooling.

## Analyst Workflow

* Findings now track `status`, `assigned_to`, `tags`, and comment counts. Assignment automatically acknowledges open findings.
* `/findings/{id}/assign`, `/findings/{id}/status`, and `/findings/{id}/tags` endpoints enforce RBAC (analyst or admin) and record audit events.
* `/findings/{id}/comments` provides immutable analyst commentary with canonical SHA-256 hashes persisted in the database for audit reconciliation.
* `/findings/{id}/timeline` aggregates audit events for a per-finding history.

## Filtering & Timeline Views

* `/findings` accepts `severity`, `status`, `tag`, `assigned_to`, `from`, and `to` filters. Results include ticket metadata and workflow counts.
* `/findings/timeline` produces per-day buckets of open, acknowledged, and resolved findings for dashboards.
* The dashboard exposes filter controls and a timeline card to highlight workflow trends.

### `/findings` response structure

The controller now returns aggregate workflow counts alongside the paginated dataset so analysts can gauge backlog distribution without issuing a second query.

```json
{
  "data": [
    { "id": "…", "status": "open", "category": "web", "tags": [] }
  ],
  "meta": { "total": 6, "limit": 50, "offset": 0 },
  "workflow_counts": {
    "pending_validation": 1,
    "open": 2,
    "invalidated": 1,
    "acknowledged": 1,
    "resolved": 1
  }
}
```

Binary static/symbolic/fuzzing findings are normalized as `open` because they lack per-record workflow transitions.

## Export Pipeline

* `POST /reports/export` renders deterministic HTML or PDF snapshots, persists the artifact to MinIO/S3, and records a `report_exports` row capturing storage bucket/key, SHA-256 checksum, requester, and filter metadata.
* `GET /reports/export` lists recent exports (filterable by scan or finding) so analysts can review retention history directly in the UI.
* `GET /reports/{id}` streams the stored artifact after verifying the checksum matches the recorded digest; the controller returns MinIO metadata headers for audit trails.
* The Next.js UI proxies downloads through `/api/reports/export`, supports both on-demand generation and fetching existing artifacts by `reportId`, and surfaces recent exports with timestamps.

## Ticketing

* `/tickets/jira` and `/tickets/github` require the `ticket:create` role. They validate scope authorization, normalize payloads, hash ticket metadata, and persist immutable records.
* Findings serialize linked tickets so analysts can review provenance directly in the UI.

## Security & Auditability

* All new endpoints reuse `record_audit_event`, ensure immutable hashes for comments/tickets, and sanitize inputs (tags, statuses, references). Report exports add `download_report` audit entries keyed by report ID, storage location, and checksum.
* Hash fields on persisted records (`metadata_hash`, `evidence_hash`, `advisories_hash`, `errors_hash`, `provenance_hash`, `payload_hash`, `content_sha256`) are guaranteed to be populated using canonical serialization so downstream systems can detect tampering.
* Role constants now include `report:export` and `ticket:create`; admin credentials receive both by default. The `/reports/{id}` download endpoint enforces both `findings:read` and `report:export` to prevent bulk exfiltration.

## Retention & MinIO Controls

* Report artifacts live under the `MEDUSA_REPORT_EXPORT_BUCKET`/`MEDUSA_REPORT_EXPORT_PREFIX` namespace (defaults: `medusa-reports`/`reports`). Operations teams can apply MinIO/S3 lifecycle policies against this prefix to match retention SLAs.
* Stored exports retain the finding IDs and scan identifiers used to generate them, enabling forensic review of which scope was shared.
* UI download links include the recorded checksum so recipients can verify integrity outside the platform.
* Local development without MinIO credentials falls back to ephemeral in-memory storage so engineers can exercise the workflow without external dependencies. This mode is non-persistent by design.

### `/reports/export` request payload

Analysts can scope exports explicitly by providing finding IDs, a scan identifier, or filter values that mirror the `/findings` collection endpoint. Payloads default to HTML generation but can request PDF snapshots as needed.

```json
{
  "format": "pdf",
  "finding_ids": ["finding-uuid-1"],
  "scan_id": "scan-uuid-1",
  "severity": "critical",
  "status": "open",
  "scope": "in_scope",
  "tag": "ops",
  "assigned_to": "analyst@example.com",
  "from": "2024-01-15T00:00:00+00:00",
  "to": "2024-01-20T00:00:00+00:00"
}
```

The export metadata stored alongside each artifact echoes the normalized filters (lower-cased values, ISO-8601 timestamps) so audit consumers can reconstruct the scope that produced a report.

Consult the updated API tests (`controller/tests/test_api_contracts.py`) for example payloads and regression coverage.
