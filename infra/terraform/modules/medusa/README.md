# Medusa Helm Module

This module deploys the Medusa platform chart into an existing EKS cluster. It
accepts upstream infrastructure outputs (EKS endpoint credentials, RDS
connection metadata, and S3 bucket identifiers) to keep the release
configuration deterministic and auditable.

## Features

- Configures local `kubernetes` and `helm` providers using the EKS API endpoint,
  CA bundle, and authentication token exported by the cluster module.
- Optionally renders a kubeconfig snippet to simplify operator access while
  maintaining short-lived tokens.
- Creates supporting Kubernetes resources depending on the selected secret
  strategy:
  - **inline** &rarr; Helm renders the secret by default. When
    `manage_inline_secret = true`, Terraform provisions the `Secret` directly
    and suppresses Helm's inline template to prevent duplication.
  - **externalSecret** &rarr; Terraform can emit an
    `external-secrets.io` manifest when `manage_external_secret = true`,
    including optional `dataFrom` and `target.template` blocks for templating
    composite secrets. The chart may render the manifest when Terraform
    management is disabled.
- Wires Helm values with RDS connection strings, S3 bucket names, and callback
  tokens generated elsewhere in Terraform.

## Usage

```hcl
module "medusa" {
  source = "./modules/medusa"

  cluster_name                       = local.cluster_name
  cluster_endpoint                   = module.eks.cluster_endpoint
  cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
  cluster_token                      = data.aws_eks_cluster_auth.medusa.token

  namespace    = local.environment_context.namespace
  release_name = local.environment_context.helm_release

  secret_name     = "medusa-secrets"
  secret_strategy = var.medusa_secret_strategy

  manage_inline_secret   = var.medusa_manage_inline_secret
  manage_external_secret = var.medusa_manage_external_secret

  database = {
    hostname          = module.rds.controller_context.hostname
    port              = module.rds.controller_context.port
    database          = module.rds.controller_context.database
    connection_string = module.rds.controller_context.connection_string
    secret_arn        = module.rds.controller_context.secret_arn
    secret_name       = module.rds.controller_context.secret_name
  }

  bucket_names = {
    artifact = module.s3.artifact_bucket.name
    fuzzing  = module.s3.artifact_bucket.name
    metadata = module.s3.artifact_bucket.name
  }

  callback_tokens = {
    nuclei        = random_password.medusa_callback["nuclei"].result
    enrichment    = random_password.medusa_callback["enrichment"].result
    binary_static = random_password.medusa_callback["binary_static"].result
    binary_fuzzing = random_password.medusa_callback["binary_fuzzing"].result
  }
}
```

## Manual steps

- Run `helm dependency update infra/helm/medusa` whenever chart dependencies
  change. The module enables `dependency_update = true`, but local charts still
  require the vendor directory to exist before `terraform apply`.
- Ensure the External Secrets operator is installed in the target cluster when
  using the `externalSecret` strategy.

