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

See the [External Secrets runbook](runbooks/EXTERNAL_SECRETS.md) for outage response steps, rotation playbooks, and validation checklists that must accompany any Terraform change touching the operator.

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

# Wire alerts into PagerDuty and Slack using the bundled template and External Secrets
observability_enable_alertmanager = true
observability_alertmanager_template_settings = {
  default_receiver = "medusa-security-slack"
  pagerduty = {
    receiver       = "medusa-security-pagerduty"
    secret_name    = "medusa-alertmanager-credentials"
    secret_key     = "pagerduty-routing-key"
  }
  slack = {
    receiver    = "medusa-security-slack"
    secret_name = "medusa-alertmanager-credentials"
    secret_key  = "slack-webhook-url"
    channel     = "#medusa-alerts"
  }
}
external_secrets_external_secrets = {
  alertmanager = {
    namespace = "observability"
    target = {
      name            = "medusa-alertmanager-credentials"
      creation_policy = "Owner"
      deletion_policy = "Retain"
    }
    data = [
      {
        secret_key = "pagerduty-routing-key"
        remote_ref = {
          key      = "medusa/prod/alertmanager"
          property = "pagerdutyRoutingKey"
        }
      },
      {
        secret_key = "slack-webhook-url"
        remote_ref = {
          key      = "medusa/prod/alertmanager"
          property = "slackWebhookUrl"
        }
      },
    ]
  }
}
```

**Grafana admin rotation.** When Terraform manages the admin secret, rotate credentials by updating `observability_grafana_admin_credentials.password` (or sourcing it from External Secrets) and re-running `terraform apply`. Terraform replaces the Kubernetes secret without downtime. If you disable secret management, provide `observability_grafana_admin_secret_name` to reference an existing Secret or ExternalSecret resource and rotate credentials there.

**External alerting.** The module exposes `observability_alertmanager_config`, but most teams should rely on the hardened `observability_alertmanager_template_settings`. Terraform renders the template, mounts bundled PagerDuty/Slack message templates, and injects the required secret names into the Helm values. Use External Secrets to project the routing keys into the `medusa-alertmanager-credentials` secret. Validate the wiring after `terraform apply`:

```bash
kubectl get externalsecret -n observability alertmanager
kubectl get secret -n observability medusa-alertmanager-credentials
kubectl exec -n observability statefulset/alertmanager-kube-prometheus-stack-alertmanager -c alertmanager -- \
  cat /etc/alertmanager/config/medusa-common.tmpl
```

If the template references additional routes (for example, `medusa_priority=page`), confirm the labels exist on incoming alerts before promoting to production.

#### Controller SLO dashboards and alerts

When `observability_mode = "kube-prometheus-stack"`, Terraform now renders the controller SLO Grafana dashboard and the associated Prometheus `PrometheusRule`. Existing clusters should import the live resources before switching the module on:

```bash
# Import the ConfigMap rendered by the previous deployment
terraform -chdir=infra/terraform import \
  module.observability.kubernetes_config_map.medusa_grafana_dashboards[0] \
  observability/medusa-grafana-dashboards

# Import the PrometheusRule that guards the controller/worker SLOs
terraform -chdir=infra/terraform import \
  module.observability.kubernetes_manifest.medusa_slo_alerts[0] \
  observability/medusa-slo-alerts

# Validate formatting and planned changes
terraform -chdir=infra/terraform plan -target=module.observability

# Lint the Grafana dashboard JSON before committing changes
jq empty infra/terraform/modules/observability/templates/grafana-medusa-controller-dashboard.json.tftpl
# Optional: validate the dashboard schema using grafana-toolkit if installed
# npx @grafana/toolkit plugin:lint --config infra/terraform/modules/observability/templates/grafana-medusa-controller-dashboard.json.tftpl
```

The dashboard surfaces HTTP latency, queue depth, and worker runtime histograms published by the controller. It now also charts the controller error ratio derived from `medusa_controller_http_request_outcomes_total` and the worker callback outcome split from `medusa_worker_callback_outcomes_total`, giving operators direct visibility into SLO burn and callback health. The PrometheusRule enforces SLO guardrails for HTTP error budget burn, controller latency, queue depth, worker runtime, and callback failures. Adjust the thresholds per environment by overriding the template file and re-running `terraform plan`.

### Pod Security Standards

Terraform owns the Medusa namespace and attaches Kubernetes Pod Security Standards (PSS) labels so admission control is deterministic across clusters. The module sets `pod-security.kubernetes.io/{enforce,audit,warn}=restricted` by default and injects the Helm override `podSecurityStandards.namespaceLabelsOnly=true`. This keeps the Helm release from attempting to recreate or manage the namespace while still enforcing `restricted` level guardrails cluster-side.

Override the PSS levels per environment by setting `namespace_pod_security_standards` in your environment `terraform.tfvars`:

```hcl
namespace_pod_security_standards = {
  enforce = "baseline"   # Runtime admission level
  audit   = "restricted"  # Audit-only warnings
  warn    = "baseline"    # Warning banner surfaced to operators
}
```

Only relax these values for tightly scoped dev clusters and document the justification in the same `tfvars` file. Production and shared environments should stick with `restricted` to maintain blast-radius isolation.

### SQLMap worker IRSA

Provision a dedicated IAM role for the SQLMap worker so Redis queue access and callback tokens stay isolated from other scanners. Extend the IRSA module wiring by adding a `sqlmap` entry to `worker_policy_documents` and referencing it from your environment configuration:

```hcl
data "aws_iam_policy_document" "sqlmap_worker" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [aws_secretsmanager_secret.sqlmap_credentials.arn]
  }
  statement {
    effect = "Allow"
    actions = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.sqlmap_dead_letter.arn]
  }
}

module "irsa" {
  source = "./modules/irsa"

  # ...existing inputs...

  worker_policy_documents = merge(
    module.s3.worker_policy_documents,
    {
      sqlmap = data.aws_iam_policy_document.sqlmap_worker.json
    },
  )
}
```

Store the SQLMap callback token, queue key, and dead-letter key in AWS Secrets Manager (or your chosen secret store) and expose them via the Medusa Helm chart's ExternalSecret configuration. The IRSA module renders the service account annotations automatically, so only the SQLMap worker pod can assume the generated role and fetch those credentials.

## Security Considerations
- Enable AWS IAM roles for service accounts (IRSA) to scope worker pod permissions.
- Encrypt RDS and S3 with KMS keys managed by the security team.
- Store Terraform state in an S3 bucket with DynamoDB state locking and MFA delete enabled.
- Run `terraform-compliance` or `tfsec` in CI to enforce guardrails before apply.
