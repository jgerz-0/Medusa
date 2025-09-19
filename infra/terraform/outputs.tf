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
