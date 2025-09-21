# Controller RBAC Model

The Medusa controller enforces role-based access control (RBAC) for every API
call. The intent is to make sensitive workflow operations auditable and
restrictable while keeping read-only observability available to analysts.

## Principal Provisioning

Principals are provisioned in the `principal_credentials` table with the
following attributes:

- **subject** – stable identifier for the caller (e.g., `svc-admin`).
- **auth_method** – `api_key`, `jwt`, or `oidc`, describing how the subject
  authenticates.
- **key_hash** – SHA-256 hash of the API key secret. Empty for JWT/OIDC subjects.
- **roles** – JSON array describing the permissions the subject holds.
- **expires_at** – optional timestamp after which the credential is considered
  inactive. Auto-provisioned OIDC principals refresh this value each login when
  a TTL is configured.
- **revoked_at** – null when active, timestamp when the credential is revoked.
- **source** – string describing how the credential was created (`manual`,
  `oidc_auto`, etc.) to support downstream automation policies.

API keys are compared using the stored hash; JWT and OIDC subjects must also be
present in this table to be accepted. The controller rejects any credential that
is not registered or that lacks roles.

## Authentication Flow

The controller authenticates requests using the following precedence rules:

1. If an `X-API-Key` (or bare bearer token) header is present, the value is
   hashed with SHA-256 and compared against active `principal_credentials`
   records where `auth_method = 'api_key'` and `revoked_at IS NULL`. The
   principal inherits the stored role set.
2. If the hash only matches revoked credentials, the controller immediately
   returns `403 Forbidden`. Revoked keys never fall back to other mechanisms.
3. Bearer tokens that include a `kid` header are validated as OpenID Connect
   tokens against the configured JWKS document. The controller maps the `sub`
   claim to an `oidc` credential and enforces the stored role set.
4. If OIDC validation is not configured or the token omits `kid`, the
   controller falls back to validating the token using the local symmetric
   `jwt_secret` and the `jwt` credential table.

All API key authentication therefore depends on presence in the
`principal_credentials` table. Operators should seed baseline service
principals using `controller.scripts.seed_principals` and manage the records
through migrations or automation pipelines so keys can be revoked centrally
without redeploying the controller.

### OIDC Auto-Provisioning Controls

Security teams can map identity-provider groups to Medusa roles without
manually pre-seeding every subject. The controller only provisions or updates
an OIDC subject when all of the following safeguards are in place:

- `MEDUSA_OIDC_AUTO_PROVISION` is `true`.
- `MEDUSA_OIDC_AUTO_PROVISION_ALLOWED_ISSUERS` includes the token's `iss`
  claim. Tokens from untrusted issuers are rejected even if other claims match.
- `MEDUSA_OIDC_GROUP_ROLE_MAP` maps IdP groups (read from the
  `MEDUSA_OIDC_GROUP_CLAIM`, default `groups`) to Medusa roles.
- `MEDUSA_OIDC_AUTO_PROVISION_ROLE_ALLOW_LIST` enumerates the roles that may be
  granted automatically. Roles outside this allow-list are ignored.
- `MEDUSA_OIDC_AUTO_PROVISION_EXPIRES_IN_SECONDS` (optional) sets a TTL that is
  refreshed on every successful login. Expired principals are denied until the
  IdP asserts an allowed group again.

When these conditions are met, `_authenticate_oidc` creates or updates a
`principal_credentials` row with `source = "oidc_auto"`. Auto-provisioned
subjects that drift from the configured role mapping trigger audit events:

- `oidc_auto_provision` – recorded whenever a new principal is created.
- `oidc_role_sync` – emitted when roles/expiration are brought back into
  alignment with IdP claims.
- `oidc_role_drift_detected` – emitted when a token asserts roles that exceed a
  manually managed credential's permissions.

Administrators can permanently block a subject by revoking the credential; the
controller refuses to re-provision any subject with a revoked record on file,
ensuring revocation is authoritative even when upstream group membership still
matches.

## Roles

The following baseline roles are supported:

| Role            | Capabilities                                                            |
|-----------------|-------------------------------------------------------------------------|
| `admin`         | Full access to all controller routes (implicit superset of other roles). |
| `scan:enqueue`  | Permission to enqueue scans via `POST /scan`.                            |
| `targets:write` | Permission to create and manage targets via `POST /targets`.             |
| `findings:read` | Permission to list findings via `GET /findings` and other read-only data.|
| `analyst`       | Convenience label for subjects limited to read-only access.              |

Routes can require multiple roles; holding `admin` always satisfies the
requirement. The `admin` role remains a superset of `targets:write` and
`findings:read`, so existing integrations using administrative credentials do
not require immediate updates.

## Enforcement Points

- `POST /scan` – requires `scan:enqueue` (or `admin`).
- `POST /targets` – requires `targets:write` (or `admin`).
- `GET /findings` – requires `findings:read` (or `admin`).
- `GET /audit-log` – requires `admin`. This route exposes sensitive telemetry
  about every privileged operation and must stay locked down.

Each RBAC decision—successful authorizations and explicit denials—is recorded
via the audit logging pipeline. This ensures post-incident review includes both
the sensitive operations that executed and the attempts that were blocked for
missing roles or revoked credentials.

### Request Rate Limiting

Authenticated principals are rate limited using a shared in-memory token bucket
to minimize credential abuse. The defaults permit 300 requests per 60 seconds
per subject. Administrators can tune the limit using the `MEDUSA_RATE_LIMIT_*`
environment variables and exempt specific automation principals by adding their
subjects to `rate_limit_exempt_subjects`. Denials are logged with
`reason=rate_limit_exceeded` to the audit log to support anomaly detection.

## Audit Log Access Workflow

The controller exposes immutable audit trails via `GET /audit-log`. This
endpoint is restricted to administrators (`admin` role) because it leaks
sensitive operational metadata:

- `actor` – principal string that performed the action.
- `action` – controller event key such as `enqueue_scan` or `list_targets`.
- `scan_id` / `finding_id` – optional foreign keys when the event relates to a
  specific scan or finding.
- `message` – human-readable context recorded by the caller.
- `evidence_snapshot` – JSON payload containing resource metadata at the time
  of the action.
- `evidence_hash` – SHA-256 digest of the snapshot to prove immutability.
- `created_at` – UTC timestamp when the event was captured.

### Request Parameters

Administrators can filter the log using optional query parameters:

- `actor` – exact match on the principal subject.
- `action` – exact match on the audit action key.
- `scan_id` – limit results to a single scan identifier.
- `limit` / `offset` – pagination controls (defaults: `limit=50`, `offset=0`).

Each response returns deterministic pagination metadata:

```json
{
  "data": [
    {
      "id": "a3e...",
      "actor": "bootstrap-admin",
      "action": "enqueue_scan",
      "message": "scheduled nuclei sweep",
      "scan_id": "c1b...",
      "finding_id": null,
      "evidence_snapshot": {
        "resource_type": "scan",
        "resource_id": "c1b...",
        "scanner": "nuclei"
      },
      "evidence_hash": "1d1f...",
      "created_at": "2024-03-08T12:15:00+00:00"
    }
  ],
  "meta": {
    "total": 42,
    "limit": 50,
    "offset": 0
  }
}
```

Every successful listing writes an additional `list_audit_log` entry so the
system can attest to who inspected the logs and when.

## Operational Workflow

1. Apply the latest Alembic migrations (`poetry run alembic upgrade head`) so
   the `principal_credentials` table is present.
2. Provision a credential record with roles using SQL migrations or an
   automated secrets workflow.
3. Distribute the API key (or JWT) to the service needing access.
4. Monitor audit logs for `insufficient role` or `invalid API key` events to
   detect misconfigurations or malicious use.

Treat API key material as sensitive. Rotate credentials by inserting a new
record and setting `revoked_at` on the prior entry.

## Credential Rotation

Credential material must be rotated whenever secrets are exposed or on a
scheduled cadence. The controller enforces a partial unique index on
`principal_credentials.subject` scoped to rows where `revoked_at IS NULL`. This
ensures only one active credential exists for a subject while retaining all
revoked entries for audit investigations.

Rotation flow:

1. Issue `POST /principals/{credential_id}/revoke` for the existing credential.
2. Issue `POST /principals` with the same subject to mint a replacement key.
3. Distribute the newly returned secret and destroy the retired material.

Historical rows remain queryable via `/principals` and in the database. They
preserve role assignments and hash fingerprints to support forensic review
without blocking future re-issuance.
