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
