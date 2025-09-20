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

## Security Considerations
- Enable AWS IAM roles for service accounts (IRSA) to scope worker pod permissions.
- Encrypt RDS and S3 with KMS keys managed by the security team.
- Store Terraform state in an S3 bucket with DynamoDB state locking and MFA delete enabled.
- Run `terraform-compliance` or `tfsec` in CI to enforce guardrails before apply.
