output "cluster_endpoint" {
  description = "Public or private endpoint used to reach the Kubernetes API server."
  value = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate authority data for kubeconfig generation."
  value = module.eks.cluster_certificate_authority_data
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL backing IRSA for workload identity."
  value = module.eks.cluster_oidc_issuer_url
}

output "node_security_group_id" {
  description = "Security group protecting the managed node groups."
  value = module.eks.node_security_group_id
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN assumed by the EKS control plane."
  value = module.eks.cluster_iam_role_arn
}

output "node_iam_role_arns" {
  description = "IAM role ARNs associated with each managed node group."
  value = module.eks.eks_managed_node_group_iam_role_arns
}

output "vpc_id" {
  description = "Identifier of the VPC securing the Medusa cluster."
  value = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet identifiers assigned to worker nodes."
  value = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "Public subnet identifiers used for ingress and NAT."
  value = module.vpc.public_subnets
}

output "encryption_key_arn" {
  description = "KMS key ARN encrypting Kubernetes secrets at rest."
  value = aws_kms_key.eks.arn
}
