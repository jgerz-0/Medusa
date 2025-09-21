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

## Export Pipeline

* `/reports/export` returns base64-encoded HTML or PDF reports with evidence snapshots, metadata, and deterministic CVSS estimates (severity-derived).
* The Next.js UI proxies downloads through `/api/reports/export` to deliver files to the browser while keeping API credentials server-side.

## Ticketing

* `/tickets/jira` and `/tickets/github` require the `ticket:create` role. They validate scope authorization, normalize payloads, hash ticket metadata, and persist immutable records.
* Findings serialize linked tickets so analysts can review provenance directly in the UI.

## Security & Auditability

* All new endpoints reuse `record_audit_event`, ensure immutable hashes for comments/tickets, and sanitize inputs (tags, statuses, references).
* Hash fields on persisted records (`metadata_hash`, `evidence_hash`, `advisories_hash`, `errors_hash`, `provenance_hash`, `payload_hash`) are guaranteed to be populated using canonical JSON serialization so downstream systems can detect tampering.
* Role constants now include `report:export` and `ticket:create`; admin credentials receive both by default.

Consult the updated API tests (`controller/tests/test_api_contracts.py`) for example payloads and regression coverage.
