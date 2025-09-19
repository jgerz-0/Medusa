# Controller RBAC Model

The Medusa controller enforces role-based access control (RBAC) for every API
call. The intent is to make sensitive workflow operations auditable and
restrictable while keeping read-only observability available to analysts.

## Principal Provisioning

Principals are provisioned in the `principal_credentials` table with the
following attributes:

- **subject** – stable identifier for the caller (e.g., `svc-admin`).
- **auth_method** – `api_key` or `jwt`, describing how the subject
  authenticates.
- **key_hash** – SHA-256 hash of the API key secret. Empty for JWT subjects.
- **roles** – JSON array describing the permissions the subject holds.
- **revoked_at** – null when active, timestamp when the credential is revoked.

API keys are compared using the stored hash; JWT subjects must also be present
in this table to be accepted. The controller rejects any credential that is not
registered or that lacks roles.

## Authentication Flow

The controller authenticates requests using the following precedence rules:

1. If an `X-API-Key` (or bare bearer token) header is present, the value is
   hashed with SHA-256 and compared against active `principal_credentials`
   records where `auth_method = 'api_key'` and `revoked_at IS NULL`. The
   principal inherits the stored role set.
2. If the hash only matches revoked credentials, the controller immediately
   returns `403 Forbidden`. Revoked keys never fall back to other mechanisms.
3. Finally, bearer tokens are validated as JWTs and mapped to `jwt`
   credentials stored in the same table.

All API key authentication therefore depends on presence in the
`principal_credentials` table. Operators should seed baseline service
principals using `controller.scripts.seed_principals` and manage the records
through migrations or automation pipelines so keys can be revoked centrally
without redeploying the controller.

## Roles

The following baseline roles are supported:

| Role            | Capabilities                                                            |
|-----------------|-------------------------------------------------------------------------|
| `admin`         | Full access to all controller routes (implicit superset of other roles). |
| `scan:enqueue`  | Permission to enqueue scans via `POST /scan`.                            |
| `targets:write` | Permission to create and manage targets (future expansion).              |
| `findings:read` | Permission to list findings and other read-only data.                    |
| `analyst`       | Convenience label for subjects limited to read-only access.              |

Routes can require multiple roles; holding `admin` always satisfies the
requirement.

## Enforcement Points

- `POST /scan` – requires `scan:enqueue` (or `admin`).
- `POST /targets` – currently requires authentication; extend with
  `targets:write` when write restrictions are needed.
- `GET /findings` – requires any authenticated principal. Read-only access is
  typically granted via `findings:read`.

Each RBAC decision is recorded via the audit logging pipeline, enabling
post-incident review of every permitted or denied operation.

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
