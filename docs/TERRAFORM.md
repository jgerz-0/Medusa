# Terraform Infrastructure

Terraform codifies the cloud footprint required for running Medusa at scale. The initial IaC work begins during Phase 5 alongside Kubernetes orchestration.

## Providers
- **AWS** – EKS (control plane + worker nodes), RDS Postgres, S3 for artifacts, IAM roles
- **Helm** – Manage in-cluster charts (Prometheus, Grafana, Medusa Helm release)
- **Kubernetes** – Apply custom resources that Helm does not cover
- **External Secrets Operator** – Optional provider for syncing secrets

## Repository Structure
```
infra/terraform
├── envs/
│   ├── dev/
│   │   └── terraform.tfvars
│   └── prod/
│       └── terraform.tfvars
├── modules/
│   ├── eks/
│   ├── rds/
│   ├── s3/
│   ├── external-secrets/
│   ├── observability/
│   └── medusa/
├── main.tf
├── variables.tf
└── outputs.tf
```

## Workflow
```bash
cd infra/terraform/envs/dev
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

### External Secrets Operator

The `external-secrets` module installs the External Secrets Operator, provisions a `SecretStore` or `ClusterSecretStore`, and feeds a Terraform-managed `ExternalSecret` into the Medusa release. Enable it by adding the following overrides to your environment `terraform.tfvars`:

```hcl
enable_external_secrets_operator   = true
external_secrets_irsa_role_arn     = "arn:aws:iam::123456789012:role/external-secrets-operator"
external_secrets_secret_store_name = "medusa-prod-cluster-secrets"
```

Terraform annotates the operator service account with the supplied IRSA role, points the secret store at AWS Secrets Manager, and configures the Medusa module to render an `ExternalSecret` that materialises the RDS credentials and callback tokens. Disable the flag in development environments to fall back to inline secrets.

### Observability

The `observability` module hardens how Prometheus and Grafana are deployed for Medusa. It supports two modes:

- `embedded` (default) – enables the Medusa chart dependencies for Prometheus/Grafana, constrains them with network policies, and keeps the data plane inside the Medusa namespace. This is ideal for development and CI clusters.
- `kube-prometheus-stack` – deploys the full Prometheus Operator stack with CRDs, Alertmanager, and hardened network policies. Medusa automatically renders a `ServiceMonitor` and waits on the CRDs so Helm does not fail.

Enable the stack in `terraform.tfvars` using the new `observability_*` variables:

```hcl
enable_observability = true
observability_mode   = "kube-prometheus-stack" # or "embedded"

# Terraform-managed Grafana credentials (rotate by updating the secret values and re-applying)
observability_manage_grafana_admin_secret = true
observability_grafana_admin_credentials = {
  username = "medusa-ops"
  password = "GENERATE_AND_ROTATE_THIS"
}

# Optional ingress and scrape tuning
observability_grafana_ingress_enabled = true
observability_grafana_ingress_hosts = [{
  host = "grafana.prod.example.com"
  paths = [{ path = "/", path_type = "Prefix" }]
}]
observability_service_monitor_interval       = "30s"
observability_service_monitor_scrape_timeout = "10s"

# Wire alerts into PagerDuty, Opsgenie, etc. using Alertmanager configuration
observability_enable_alertmanager = true
observability_alertmanager_config = <<-EOF
route:
  receiver: pagerduty
receivers:
  - name: pagerduty
    pagerduty_configs:
      - routing_key: ${var.pagerduty_routing_key}
EOF
```

**Grafana admin rotation.** When Terraform manages the admin secret, rotate credentials by updating `observability_grafana_admin_credentials.password` (or sourcing it from External Secrets) and re-running `terraform apply`. Terraform replaces the Kubernetes secret without downtime. If you disable secret management, provide `observability_grafana_admin_secret_name` to reference an existing Secret or ExternalSecret resource and rotate credentials there.

**External alerting.** The module exposes `observability_alertmanager_config` so Alertmanager can forward incidents to PagerDuty, Slack, email, or SIEM webhooks. Store sensitive tokens in AWS Secrets Manager and render them via External Secrets, then reference the secret in your YAML using the standard Alertmanager templating syntax.

## Security Considerations
- Enable AWS IAM roles for service accounts (IRSA) to scope worker pod permissions.
- Encrypt RDS and S3 with KMS keys managed by the security team.
- Store Terraform state in an S3 bucket with DynamoDB state locking and MFA delete enabled.
- Run `terraform-compliance` or `tfsec` in CI to enforce guardrails before apply.
