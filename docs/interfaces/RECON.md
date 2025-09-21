# Recon Job & Callback Schema

The recon worker synchronises authorised asset inventories into Medusa.
Jobs are enqueued by `POST /recon/jobs` and the worker posts discoveries to
`POST /internal/recon` using the shared `X-Callback-Token` secret.

## Job Request (`POST /recon/jobs`)

```jsonc
{
  "source": "inventory:web",           // friendly feed identifier
  "feed": {
    "type": "csv",                    // "csv" or "api"
    "url": "https://assets.example/recon.csv",
    "asset_column": "asset",          // column containing the asset string
    "asset_type_column": "asset_type"  // optional column with explicit types
  },
  "authorized_scopes": ["example.com", "10.0.0.0/24"],
  "labels": ["inventory", "quarterly"]
}
```

### Field Reference

| Field | Type | Notes |
| ----- | ---- | ----- |
| `source` | string | Human readable source label recorded with discoveries. |
| `feed.type` | enum | `csv` or `api`. Determines how the worker parses the feed. |
| `feed.url` | string | HTTPS/HTTP or `file://` URL pointing at the inventory feed. |
| `feed.asset_column` | string | CSV column containing the asset string (default `asset`). |
| `feed.asset_type_column` | string | Optional CSV column that supplies explicit types (`domain`, `ipv4`, etc.). |
| `feed.delimiter` | string | Optional CSV delimiter (default `,`). |
| `feed.items_path` | array | For API feeds, keys used to traverse nested JSON structures. |
| `feed.asset_field` | string | API field containing the asset value (default `asset`). |
| `feed.type_field` | string | API field providing an explicit asset type hint. |
| `authorized_scopes` | array | One or more domain/IP/CIDR values that bound the authorised inventory. |
| `labels` | array | Optional labels recorded in discovery metadata. |

The controller injects `job_id`, `callback_url`, and audit metadata before the
payload is delivered to Redis.

## Worker Callback (`POST /internal/recon`)

```jsonc
{
  "job_id": "job-1",
  "source": "inventory:web",
  "retrieved_at": "2025-04-12T10:15:00Z",
  "assets": [
    {
      "asset_type": "domain",
      "normalized_value": "app.example.com",
      "raw_value": "App.Example.com",
      "matched_scope": "example.com",
      "occurrences": 2,
      "metadata": {"labels": ["inventory"]},
      "first_seen": "2025-04-12T10:15:00Z",
      "last_seen": "2025-04-12T10:15:00Z"
    }
  ]
}
```

### Field Reference

| Field | Type | Notes |
| ----- | ---- | ----- |
| `job_id` | string | Identifier provided by the controller when scheduling the job. |
| `source` | string | Mirrors the `source` supplied during scheduling. |
| `retrieved_at` | RFC3339 timestamp | When the feed was retrieved. Used as a fallback for timestamps. |
| `assets` | array | One or more normalized assets. Requests with an empty list are discarded. |
| `asset_type` | enum | `domain`, `ipv4`, `ipv6`, or `url`. |
| `normalized_value` | string | Canonical, lowercase value used for deduplication. |
| `raw_value` | string | Original asset string prior to normalization. |
| `matched_scope` | string | Authorised scope that permitted the asset (domain or CIDR). |
| `occurrences` | integer | Number of times the asset appeared in the feed. Must be ≥ 1. |
| `metadata` | object | Optional contextual labels or feed hints. |
| `first_seen`, `last_seen` | RFC3339 timestamp | Observed timestamps for the asset within the feed. |

## Controller Behaviour

* New assets are stored in `recon_discoveries` with `status="new"`. Subsequent
  callbacks increment the `occurrences` counter and update the observed window.
* Matching `matched_scope` values constrain analyst approvals: assets can only
  be promoted into targets if the requested scope remains within the authorised
  boundary.
* `POST /recon/discoveries/{id}/approve` creates a new authorised target and
  records an audit log entry documenting the approver, target identifier, and
  final scope.

## Security Considerations

* Recon callbacks require the dedicated `X-Callback-Token` header configured in
  `Settings.recon_callback_token`.
* Assets that fall outside the `authorized_scopes` are discarded by the worker
  before reaching the controller, ensuring no accidental scope expansion.
* All approvals are RBAC protected (`targets:write`) and produce immutable audit
  log entries for forensic review.
