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

## Security Considerations
- Enable AWS IAM roles for service accounts (IRSA) to scope worker pod permissions.
- Encrypt RDS and S3 with KMS keys managed by the security team.
- Store Terraform state in an S3 bucket with DynamoDB state locking and MFA delete enabled.
- Run `terraform-compliance` or `tfsec` in CI to enforce guardrails before apply.
