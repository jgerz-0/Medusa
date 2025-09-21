locals {
  project_name = coalesce(var.project_name, "medusa-pentest")
  environment  = coalesce(var.environment, "dev")
  aws_region   = coalesce(var.aws_region, "us-east-1")
  aws_profile  = var.aws_profile != null && var.aws_profile != "" ? var.aws_profile : null

  cluster_name = coalesce(var.cluster_name, "${local.project_name}-${local.environment}")

  # Common tags enforce the security posture and traceability requirements we
  # apply to every AWS asset.
  common_tags = {
    Project     = local.project_name
    Environment = local.environment
    ManagedBy   = "terraform"
    Security    = "medusa-pentest-platform"
  }

  # Environment-specific hints keep our automation predictable without forcing
  # hard-coded names into every module. These values intentionally align with
  # Docker/Helm defaults used in CI workflows.
  environment_settings = {
    dev = {
      namespace        = "medusa-dev"
      kube_context     = "medusa-dev"
      helm_release     = "${local.project_name}-dev"
      container_repo   = "ghcr.io/medusa/dev"
    }
    prod = {
      namespace        = "medusa-prod"
      kube_context     = "medusa-prod"
      helm_release     = "${local.project_name}"
      container_repo   = "ghcr.io/medusa/prod"
    }
  }

  environment_context = lookup(
    local.environment_settings,
    local.environment,
    {
      namespace      = "medusa-${local.environment}"
      kube_context   = local.cluster_name
      helm_release   = local.cluster_name
      container_repo = "ghcr.io/medusa/${local.environment}"
    }
  )

  state_backend = {
    bucket         = coalesce(var.state_bucket, "medusa-terraform-state")
    dynamodb_table = coalesce(var.state_dynamodb_table, "medusa-terraform-locks")
    key_prefix     = coalesce(var.state_key_prefix, local.environment)
  }

  registry_credentials = {
    server   = coalesce(var.container_registry_server, "ghcr.io")
    username = coalesce(var.container_registry_username, "medusa-ci")
    password = coalesce(var.container_registry_password, "REPLACE_ME")
  }

  helm_registry_credentials = {
    repository = coalesce(var.helm_repository_url, "oci://ghcr.io/medusa/charts")
    username   = coalesce(var.helm_repository_username, "medusa-ci")
    password   = coalesce(var.helm_repository_password, "REPLACE_ME")
  }
}
