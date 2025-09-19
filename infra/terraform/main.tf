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

locals {
  eks_context = {
    cluster_endpoint = module.eks.cluster_endpoint
    cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
    cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
    node_security_group_id = module.eks.node_security_group_id
    cluster_iam_role_arn = module.eks.cluster_iam_role_arn
    node_iam_role_arns = module.eks.node_iam_role_arns
  }
}
