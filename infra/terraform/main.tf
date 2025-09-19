terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }

    externalsecrets = {
      source  = "external-secrets/external-secrets"
      version = "~> 0.9"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    bucket         = "medusa-terraform-state"
    key            = "global/platform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "medusa-terraform-locks"
  }
}

# AWS is the control plane for almost everything in the platform. We rely on
# Terraform locals and variables to keep regions, project naming, and tagging
# consistent across environments.
provider "aws" {
  region  = local.aws_region
  profile = local.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

# Kubernetes resources are managed via kubeconfig by default. This keeps the
# provider lean and defers credential sourcing to the caller (normally a CI/CD
# job or a security engineer's workstation with short-lived credentials).
provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = coalesce(var.kubeconfig_context, local.environment_context.kube_context)
}

# Helm releases reuse the same Kubernetes authentication material to avoid
# duplicate credential stores.
provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = coalesce(var.kubeconfig_context, local.environment_context.kube_context)
  }

  registry_config_path = var.helm_registry_config
}

# External Secrets needs access to the target Kubernetes API just like Helm.
provider "externalsecrets" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = coalesce(var.kubeconfig_context, local.environment_context.kube_context)
  }
}

module "eks" {
  source = "./modules/eks"

  vpc_cidr = var.vpc_cidr
  availability_zones = var.availability_zones
  private_subnet_cidrs = var.private_subnet_cidrs
  public_subnet_cidrs = var.public_subnet_cidrs
  cluster_name = local.cluster_name
  cluster_version = var.cluster_version
  cluster_endpoint_public_access = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  cluster_log_types = var.cluster_log_types
  cloudwatch_log_retention_in_days = var.cloudwatch_log_retention_in_days
  cluster_iam_role_name = var.cluster_iam_role_name
  cluster_iam_role_additional_policy_arns = var.cluster_iam_role_additional_policy_arns
  node_iam_role_name = var.node_iam_role_name
  node_iam_role_additional_policy_arns = var.node_iam_role_additional_policy_arns
  default_node_group_disk_size = var.default_node_group_disk_size
  managed_node_groups = var.managed_node_groups
  tags = local.common_tags
}

data "aws_eks_cluster_auth" "medusa" {
  name = local.cluster_name

  depends_on = [module.eks]
}

resource "random_password" "medusa_callback" {
  for_each = {
    nuclei        = true
    enrichment    = true
    binary_static = true
    binary_fuzzing = true
  }

  length  = 40
  special = false
}

module "medusa" {
  source = "./modules/medusa"

  cluster_name                       = local.cluster_name
  cluster_endpoint                   = module.eks.cluster_endpoint
  cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
  cluster_token                      = data.aws_eks_cluster_auth.medusa.token

  namespace    = local.environment_context.namespace
  release_name = local.environment_context.helm_release

  secret_name     = var.medusa_secret_name
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

  bucket_names = merge(
    {
      artifact = module.s3.artifact_bucket.name
      fuzzing  = module.s3.artifact_bucket.name
      metadata = module.s3.artifact_bucket.name
    },
    var.medusa_bucket_overrides,
  )

  callback_tokens = {
    nuclei         = random_password.medusa_callback["nuclei"].result
    enrichment     = random_password.medusa_callback["enrichment"].result
    binary_static  = random_password.medusa_callback["binary_static"].result
    binary_fuzzing = random_password.medusa_callback["binary_fuzzing"].result
  }

  inline_secret_overrides       = var.medusa_inline_secret_overrides
  external_secret_configuration = var.medusa_external_secret_configuration
  controller_additional_env     = var.medusa_controller_additional_env
  extra_values                  = var.medusa_extra_values
  common_labels = merge(
    {
      "app.kubernetes.io/managed-by" = "terraform"
      "medusa.security/environment"  = local.environment
      "medusa.security/project"      = local.project_name
    },
    var.medusa_additional_labels,
  )
  render_operator_kubeconfig = var.medusa_render_operator_kubeconfig
  helm_timeout_seconds       = var.medusa_helm_timeout_seconds

  depends_on = [module.eks, module.rds, module.s3]
}

module "s3" {
  source = "./modules/s3"

  project_name = local.project_name
  environment  = local.environment

  artifact_bucket_name   = var.artifact_bucket_name
  artifact_bucket_prefix = var.artifact_bucket_prefix
  artifact_bucket_suffix = var.artifact_bucket_suffix
  force_destroy          = var.artifact_bucket_force_destroy
  versioning_enabled     = var.artifact_bucket_versioning_enabled

  enable_artifact_expiration           = var.artifact_enable_expiration
  artifact_retention_days              = var.artifact_retention_days
  enable_noncurrent_version_expiration = var.artifact_enable_noncurrent_version_expiration
  noncurrent_version_retention_days    = var.artifact_noncurrent_version_retention_days
  abort_incomplete_multipart_upload_days = var.artifact_abort_incomplete_multipart_upload_days

  worker_access = var.artifact_worker_prefixes

  create_kms_key                   = var.artifact_create_kms_key
  kms_key_arn                      = var.artifact_kms_key_arn
  kms_key_alias                    = var.artifact_kms_key_alias
  kms_key_deletion_window_in_days  = var.artifact_kms_deletion_window_in_days

  tags = local.common_tags
}

module "rds" {
  source = "./modules/rds"

  database_name        = var.rds_database_name
  instance_class       = var.rds_instance_class
  engine               = var.rds_engine
  engine_version       = var.rds_engine_version
  port                 = var.rds_port
  allocated_storage    = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  instance_identifier  = var.rds_instance_identifier
  vpc_id               = module.eks.vpc_id
  subnet_ids           = module.eks.private_subnet_ids
  allowed_security_group_ids = [module.eks.node_security_group_id]
  master_username      = var.rds_master_username
  kms_key_arn          = var.rds_kms_key_arn
  master_secret_kms_key_arn = var.rds_master_secret_kms_key_arn
  backup_retention_period = var.rds_backup_retention_period
  preferred_backup_window = var.rds_preferred_backup_window
  preferred_maintenance_window = var.rds_preferred_maintenance_window
  multi_az             = var.rds_multi_az
  deletion_protection  = var.rds_deletion_protection
  skip_final_snapshot  = var.rds_skip_final_snapshot
  apply_immediately    = var.rds_apply_immediately
  monitoring_interval  = var.rds_monitoring_interval
  iam_database_authentication_enabled = var.rds_iam_authentication_enabled
  performance_insights_enabled        = var.rds_performance_insights_enabled
  performance_insights_kms_key_arn    = var.rds_performance_insights_kms_key_arn
  master_secret_name                  = var.rds_master_secret_name
  master_secret_description           = var.rds_master_secret_description
  master_secret_rotation_enabled      = var.rds_master_secret_rotation_enabled
  master_secret_rotation_lambda_arn   = var.rds_master_secret_rotation_lambda_arn
  master_secret_rotation_automatically_after_days = var.rds_master_secret_rotation_automatically_after_days
  tags = local.common_tags
}

locals {
  eks_context = {
    cluster_endpoint = module.eks.cluster_endpoint
    cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
    cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
    node_security_group_id = module.eks.node_security_group_id
    cluster_iam_role_arn = module.eks.cluster_iam_role_arn
    node_iam_role_arns = module.eks.node_iam_role_arns
  }

  artifact_storage_context = module.s3.context

  rds_context = module.rds.controller_context

  rds_network = {
    security_group_id  = module.rds.security_group_id
    subnet_group_name  = module.rds.subnet_group_name
    database_identifier = module.rds.database_identifier
  }
}
