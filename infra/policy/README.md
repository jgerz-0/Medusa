# Policy bundles for CI

These Rego policies provide policy-as-code guardrails enforced by the CI pipeline. Extend
these policies to encode Medusa's security baselines for Terraform modules, Kubernetes
manifests, Dockerfiles, and Helm charts.

## Conftest execution targets

- `infra/terraform` – Terraform modules, providers, and state configuration.
- `infra/helm/medusa` – Helm chart templates rendered via `--input helm`.
- `infra/docker` – Dockerfiles and Compose manifests.

CI treats any `deny` rule evaluation as a failing condition. Start with the provided
baseline allow policy and layer additional packages per domain, e.g. `terraform.rego`,
`helm.rego`, or `docker.rego`.

## Local usage

Run the same conftest commands that CI executes:

```bash
conftest test infra/terraform --policy infra/policy
conftest test infra/docker --policy infra/policy
conftest test infra/helm/medusa --policy infra/policy --input helm
```

Add new Rego files under this directory to expand the enforcement surface.
