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
