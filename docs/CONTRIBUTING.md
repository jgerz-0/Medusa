# Contributing to Medusa

The Medusa platform orchestrates automated penetration testing, binary analysis, and CVE enrichment
pipelines. This repository is the coordination point for the controller services, scanning workers,
frontend portal, and supporting infrastructure-as-code. Follow the practices below to keep
contributions deterministic, auditable, and secure.

## Prerequisites

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

Thank you for helping to evolve Medusa's automated security testing platform.
