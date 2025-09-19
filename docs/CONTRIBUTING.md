# Contributing Guidelines

The Medusa platform orchestrates automated penetration testing, binary analysis, and CVE enrichment
pipelines. This repository is the coordination point for the controller services, scanning workers,
frontend portal, and supporting infrastructure-as-code. Follow the practices below to keep
contributions deterministic, auditable, and secure.

## Getting Started
1. Fork the repository and create a feature branch.
2. Install dependencies using the instructions in [README.md](../README.md).
3. Copy `.env.example` files to `.env` per service and populate local-only secrets.
4. Apply database migrations and seed local scope data:
   ```bash
   cd controller
   poetry run alembic upgrade head
   poetry run python scripts/seed_targets.py
   ```
5. Run the full lint/test suite before opening a pull request.

## Development Standards
- **Python**
  - Format with `black` and check typing with `mypy`.
  - Prefer explicit imports and avoid wildcard patterns.
  - Write docstrings for public functions describing validation and security considerations.
- **Node/TypeScript**
  - Use `pnpm lint` and `pnpm test`.
  - Keep API clients typed and document any unsafe casting.
- **Infrastructure-as-code**
  - Validate Terraform via `terraform fmt` and `terraform validate`.
  - Run `helm lint` and `kubeconform` for Kubernetes manifests.

## Adding a New Scanner or Agent
1. Create a new worker under `workers/<domain>/<tool>` with a `Dockerfile` and entrypoint.
2. Define the JSON schema for the worker's output in `docs/interfaces/` and include sample payloads.
3. Implement controller-side validation to ensure scope compliance before dispatching jobs.
4. Update Docker Compose or Helm manifests if the scanner requires additional services.
5. Document operational notes in `docs/SCANNERS.md` and link from the README.
6. Add unit/integration tests plus fixtures demonstrating deterministic findings.

## Database migrations
- Generate schema changes with `poetry run alembic revision --autogenerate -m "describe_change"`.
- Validate that models and migrations are in sync before pushing: `poetry run python scripts/check_migrations.py`.
- Ensure seed data stays within authorized test scope; update `scripts/seed_targets.py` for new demo assets.

## Pull Request Checklist
- Tests and linters pass locally and in CI.
- Documentation updated alongside code changes.
- Security implications discussed in the PR description.
- Include screenshots or CLI transcripts when modifying UX flows.

## Communication
- Use GitHub Issues for roadmap tasks aligned with the phase milestones.
- Join the weekly architecture sync to review upcoming changes.
- For urgent security topics, escalate to the security engineering channel.


### Python toolchain

- Install [Poetry 1.7+](https://python-poetry.org/docs/#installation) for dependency management.
- Use Python **3.11** (CPython) for all controller and worker services. We recommend
  [`pyenv`](https://github.com/pyenv/pyenv) or the system package manager to manage interpreters.
- Bootstrap environments:

  ```bash
  cd controller
  poetry install --with dev

  cd ../workers/web/nuclei
  poetry install --with dev
  ```

### Node.js toolchain

- Install Node.js **20.0+** and [pnpm 8+](https://pnpm.io/installation).
- Install frontend dependencies from the repository root:

  ```bash
  cd frontend
  pnpm install
  ```

## Linting and testing

Security automation must be deterministic. Always run the following before opening a pull request:

```bash
poetry run ruff check controller workers/web/nuclei
poetry run mypy controller workers/web/nuclei
poetry run pytest controller/tests workers/web/nuclei/tests

cd frontend
pnpm lint
pnpm run typecheck
```

## Commit hygiene

- Enable the provided pre-commit hooks:

  ```bash
  pre-commit install
  ```

- Use descriptive commit messages that explain intent and potential risk reductions.
- Do not commit secrets, credentials, or production scope definitions.

## Code review expectations

- Changes touching `infra/` must include Terraform/Helm/Docker validation steps.
- New agents or workers must document JSON request/response schemas.
- Frontend PRs should attach screenshots or recordings when user-facing changes occur.

## Security posture

- Assume adversarial conditions: validate inputs, enforce RBAC, and log decisions.
- Deterministic scanner results remain the source of truth; AI enrichment is additive only.
- Follow least privilege when modifying Kubernetes manifests or Terraform modules.

## RBAC quick reference

- **Administrators (`admin`)** – may issue/revoke credentials, review the audit log, manage
  target scope, and enqueue scans or enrichment jobs. Admin API keys carry the full
  `DEFAULT_ADMIN_ROLES` set.
- **Analysts (`analyst`)** – limited to operating scans, viewing findings, and enqueueing
  enrichment. Analysts cannot view `/principals` or mutate credentials.
- **Service roles** – purpose-specific scopes such as `scan:enqueue` or
  `enrich:enqueue`. Grant only the minimum roles required for automation.

Authorization responses are deterministic:

- API keys are hashed with `_hash_secret` on ingress and matched against
  `principal_credentials.key_hash`.
- Revoked or unauthorized attempts are denied through the `access_denied` audit event,
  capturing the required roles, granted roles, and a rotation fingerprint for each key.
- Every denial writes to `audit_log`, enabling SOC teams to trace credential misuse.

## Credential rotation procedures

Controller credentials are short-lived secrets; rotate them whenever an operator leaves the
engagement, a secret is exposed, or during scheduled quarterly maintenance.

### API keys

1. Authenticate with an administrator credential (`admin` role) and list existing principals:
   ```bash
   curl -H "X-API-Key: <admin-key>" https://controller.internal/principals
   ```
2. Issue a replacement API key with the same roles using the admin-only creation endpoint. The
   controller will return the clear-text secret once; store it in the team password vault:
   ```bash
   curl -X POST -H "X-API-Key: <admin-key>" \
        -H "Content-Type: application/json" \
        -d '{"subject": "svc-recon-v2", "auth_method": "api_key", "roles": ["scan:enqueue"]}' \
        https://controller.internal/principals
   ```
3. Update every service that used the old key to the new secret and validate access. For automation,
   re-run CI jobs that enqueue scans to ensure the queue accepts the new credential.
4. Revoke the superseded key:
   ```bash
   curl -X POST -H "X-API-Key: <admin-key>" \
        https://controller.internal/principals/<credential-id>/revoke
   ```
5. Validate rotation telemetry:
   - Retry an authenticated call with the revoked key; it must return `401` with `"API key revoked"`.
   - Query `/audit-log` as an admin and confirm an `access_denied` record exists with
     `reason="credential_revoked"` and a `rotation.key_fingerprint` matching the truncated
     hash returned during issuance.
   - Ensure no clear-text secrets appear in audit payloads; only hashed fingerprints are stored.

### JWT subjects

1. Confirm the subject exists in `/principals` with the expected role set.
2. Update the identity provider or signing automation to stop issuing tokens for the subject you plan
   to revoke, or generate a new subject for replacement tokens.
3. If replacing the subject entirely, create a new JWT principal via `/principals` with the
   appropriate roles and propagate the new subject claim to dependent services.
4. Revoke the legacy subject with `/principals/<credential-id>/revoke` and confirm existing tokens now
   fail with `403`.
5. Document the rotation in the operations log, including the new subject identifier and affected
   services.

Thank you for helping to evolve Medusa's automated security testing platform.
