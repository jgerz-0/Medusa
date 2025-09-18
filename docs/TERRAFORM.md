
---

# 🌍 docs/TERRAFORM.md

```markdown
# Terraform Infrastructure

## Providers
- AWS (EKS, RDS, S3)
- Helm provider (install Prometheus, Grafana)
- Kubernetes provider (deploy app)

## Structure
terraform/
├── main.tf
├── variables.tf
├── outputs.tf

## Features
- EKS cluster
- RDS Postgres
- S3 bucket for artifacts
- IAM roles for workers
- Helm releases for in-cluster services

## Usage
```bash
terraform init
terraform plan
terraform apply
