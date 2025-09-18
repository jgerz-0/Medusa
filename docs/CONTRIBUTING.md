# Contributing Guidelines

Thank you for investing in Medusa. We focus on security-first automation, deterministic scanner outputs, and transparent enrichment. Contributions should maintain those principles.

## Getting Started
1. Fork the repository and create a feature branch.
2. Install dependencies using the instructions in [README.md](../README.md).
3. Copy `.env.example` files to `.env` per service and populate local-only secrets.
4. Run the full lint/test suite before opening a pull request.

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

## Pull Request Checklist
- Tests and linters pass locally and in CI.
- Documentation updated alongside code changes.
- Security implications discussed in the PR description.
- Include screenshots or CLI transcripts when modifying UX flows.

## Communication
- Use GitHub Issues for roadmap tasks aligned with the phase milestones.
- Join the weekly architecture sync to review upcoming changes.
- For urgent security topics, escalate to the security engineering channel.
