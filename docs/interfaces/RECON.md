# Recon Job & Callback Schema

The recon worker enumerates authorised assets via two modes:

1. **Feed synchronisation** – ingest third-party inventories (CSV/API) to keep
   Medusa aligned with existing asset registries.
2. **Active discovery** – orchestrate deterministic tooling (`subfinder`,
   `amass`, `httpx`) against registered targets to surface new subdomains,
   exposed ports, and service fingerprints.

Jobs are enqueued by `POST /recon/jobs`; results are pushed to
`POST /internal/recon` using the shared `X-Callback-Token` secret.

## Job Request (`POST /recon/jobs`)

```jsonc
{
  "source": "operations:attack-surface",
  "mode": "active",                     // "active" or "feed"
  "targets": [
    {
      "target_id": "target-1",
      "scope": "example.com",
      "asset_type": "domain",          // domain, ipv4, or ipv6
      "seed_assets": ["portal.example.com"]
    }
  ],
  "tools": {
    "subfinder": true,
    "amass": true,
    "httpx": {
      "enabled": true,
      "httpx_ports": [80, 443, 8443],
      "httpx_probe_tls": true,
      "httpx_follow_redirects": false
    }
  },
  "labels": ["attack-surface", "quarterly"]
}
```

### Feed Mode Payload

```jsonc
{
  "source": "inventory:web",
  "mode": "feed",
  "feed": {
    "type": "csv",                    // "csv" or "api"
    "url": "https://assets.example/recon.csv",
    "asset_column": "asset",
    "asset_type_column": "asset_type"
  },
  "authorized_scopes": ["example.com", "10.0.0.0/24"],
  "labels": ["inventory", "quarterly"]
}
```

### Field Reference

| Field | Type | Notes |
| ----- | ---- | ----- |
| `source` | string | Human readable label recorded with discoveries and audit events. |
| `mode` | enum | `active` triggers tooling orchestration; `feed` performs CSV/API ingestion. Defaults to `feed`. |
| `targets` | array | **Active mode only.** Controller-resolved targets with enforced scopes. Empty in feed mode. |
| `targets[].scope` | string | Canonical scope stored for the target. Used to derive authorised boundaries. |
| `targets[].asset_type` | enum | `domain`, `ipv4`, or `ipv6`. Controls which tooling executes. |
| `targets[].seed_assets` | array | Optional seed hosts/IPs that stay within the stored scope. The worker rejects out-of-scope seeds. |
| `tools` | object | **Active mode only.** Declarative toggles for `subfinder`, `amass`, and `httpx`. Missing keys fall back to safe defaults. |
| `tools.httpx.httpx_ports` | array | Optional port override. Non-numeric or out-of-range values are ignored. |
| `feed` | object | **Feed mode only.** Mirrors the historical ingestion contract (`csv`/`api`). |
| `authorized_scopes` | array | Mandatory in feed mode. For active jobs this list is derived automatically from the selected targets. |
| `labels` | array | Optional analyst labels persisted alongside each discovery. |

The controller injects `job_id`, `callback_url`, the resolved `authorized_scopes`
and audit metadata before publishing the payload to Redis.

## Worker Callback (`POST /internal/recon`)

```jsonc
{
  "job_id": "job-1",
  "source": "operations:attack-surface",
  "retrieved_at": "2025-04-12T10:15:00Z",
  "authorized_scopes": ["example.com"],
  "execution": {
    "mode": "active",
    "targets": [
      {
        "target_id": "target-1",
        "scope": "example.com",
        "asset_type": "domain",
        "seed_assets": ["portal.example.com"]
      }
    ],
    "tools": {
      "subfinder": true,
      "amass": true,
      "httpx": true,
      "httpx_ports": [80, 443, 8443]
    }
  },
  "assets": [
    {
      "asset_type": "domain",
      "normalized_value": "app.example.com",
      "raw_value": "App.Example.com",
      "matched_scope": "example.com",
      "occurrences": 1,
      "metadata": {
        "target_id": "target-1",
        "target_scope": "example.com",
        "sources": ["subfinder", "target-scope"]
      },
      "first_seen": "2025-04-12T10:15:00Z",
      "last_seen": "2025-04-12T10:15:00Z"
    },
    {
      "asset_type": "url",
      "normalized_value": "https://app.example.com",
      "raw_value": "https://app.example.com",
      "matched_scope": "example.com",
      "metadata": {
        "target_id": "target-1",
        "host": "app.example.com",
        "port": 443,
        "service": {
          "status_code": 200,
          "webserver": "nginx",
          "technologies": ["Go"],
          "tls": true
        },
        "sources": ["httpx"],
        "target_scope": "example.com"
      }
    }
  ]
}
```

### Field Reference

| Field | Type | Notes |
| ----- | ---- | ----- |
| `job_id` | string | Identifier provided by the controller when scheduling the job. |
| `source` | string | Mirrors the `source` supplied during scheduling. |
| `retrieved_at` | RFC3339 timestamp | When the job completed. Used as a fallback for asset timestamps. |
| `authorized_scopes` | array | Scopes enforced by the worker. Any asset outside these bounds is discarded before delivery. |
| `execution.mode` | enum | Echoes the job mode (`active` or `feed`). |
| `execution.targets` | array | Optional context describing which targets were enumerated in active mode. Empty for feed mode. |
| `execution.tools` | object | Tooling toggles applied during the run. Useful for audit/forensic review. |
| `assets` | array | One or more normalised assets. Empty submissions are rejected. |
| `asset_type` | enum | `domain`, `ipv4`, `ipv6`, or `url`. |
| `normalized_value` | string | Canonical, lowercase representation used for deduplication. |
| `raw_value` | string | Original asset string. |
| `matched_scope` | string | Authorised scope that permitted the asset (domain or CIDR). |
| `occurrences` | integer | Number of times the asset appeared in the source payload. Must be ≥ 1. |
| `metadata` | object | Contextual metadata such as tooling sources, target linkage, service fingerprints, or analyst labels. |
| `first_seen`, `last_seen` | RFC3339 timestamp | Observed timestamps for the asset in the job output. |

## Controller Behaviour

* New assets are persisted in `recon_observations` (per-run detail) and
  aggregated into `recon_discoveries` with `status="new"`.
* When an existing discovery changes scope or metadata, the controller records a
  reconciliation audit event to highlight potential scope growth.
* Matching `matched_scope` values constrain analyst approvals: assets can only
  be promoted into targets if the requested scope remains within the authorised
  boundary.
* `POST /recon/discoveries/{id}/approve` creates a new authorised target and
  records the approver, chosen scope, and related audit metadata.

## Security Considerations

* Recon callbacks must include the `X-Callback-Token` configured in
  `Settings.recon_callback_token`.
* Active jobs only allow controller-selected targets. Seed assets are filtered
  to remain within each stored scope before tooling executes.
* All tooling binaries are executed via fixed allow-listed arguments, ensuring
  deterministic behaviour suitable for high-assurance environments.
* Approvals and scope changes are RBAC controlled (`targets:write`) and emit
  immutable audit log entries for forensic review.
