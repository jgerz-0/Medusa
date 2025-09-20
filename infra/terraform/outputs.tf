output "cluster_name" {
  description = "Resolved Kubernetes cluster name for the selected environment."
  value       = local.cluster_name
}

output "common_tags" {
  description = "Standard tags applied to all AWS resources."
  value       = local.common_tags
}

output "environment_context" {
  description = "Environment metadata used for Helm, Docker, and namespace conventions."
  value       = local.environment_context
}

output "state_backend" {
  description = "Computed remote state backend settings to keep CLI usage consistent."
  value       = local.state_backend
}

output "eks_context" {
  description = "Resolved EKS integration values (endpoint, CA, OIDC, and IAM roles)."
  value       = local.eks_context
}

output "eks_network" {
  description = "Identifiers for the VPC and subnets that back the Medusa cluster."
  value = {
    vpc_id              = module.eks.vpc_id
    private_subnet_ids  = module.eks.private_subnet_ids
    public_subnet_ids   = module.eks.public_subnet_ids
    node_security_group = module.eks.node_security_group_id
  }
}

output "eks_encryption_key_arn" {
  description = "KMS key ARN encrypting Kubernetes secrets for the cluster."
  value       = module.eks.encryption_key_arn
}

output "rds_context" {
  description = "Connection metadata and credential references for the Medusa controller database."
  value       = local.rds_context
}

output "rds_network" {
  description = "Networking primitives securing the controller database."
  value       = local.rds_network
}

output "rds_master_credentials_secret_arn" {
  description = "Secrets Manager ARN storing the controller master credentials."
  value       = module.rds.master_credentials_secret_arn
}

output "artifact_bucket" {
  description = "Artifact bucket identifiers for storing scan evidence."
  value       = module.s3.artifact_bucket
}

output "artifact_controller_policy_document" {
  description = "IAM policy document granting the controller wide access to artifact storage."
  value       = module.s3.controller_policy_document
}

output "artifact_worker_policy_documents" {
  description = "IAM policy documents scoped to worker prefixes for IRSA bindings."
  value       = module.s3.worker_policy_documents
}

output "artifact_storage" {
  description = "Aggregated artifact storage configuration consumed by downstream modules."
  value       = module.s3.context
}

output "medusa_irsa" {
  description = "IAM Roles for Service Accounts (IRSA) metadata for the Medusa deployment."
  value = {
    enabled    = module.irsa.enabled
    controller = module.irsa.controller
    workers    = module.irsa.workers
  }
}

output "external_secrets" {
  description = "External Secrets Operator deployment context."
  value = {
    enabled          = module.external_secrets.enabled
    secret_store = {
      name = module.external_secrets.secret_store_name
      kind = module.external_secrets.secret_store_kind
    }
    service_account = module.external_secrets.service_account_name
  }
}
