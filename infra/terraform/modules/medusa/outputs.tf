output "release_name" {
  description = "Name of the Helm release managing the Medusa workloads."
  value       = helm_release.medusa.name
}

output "namespace" {
  description = "Namespace housing the Medusa deployment."
  value       = var.namespace
}

output "secret_name" {
  description = "Secret name referenced by the Medusa chart."
  value       = var.secret_name
}

output "rendered_helm_values" {
  description = "Composite Helm values applied to the Medusa release for auditing."
  value       = local.base_helm_values
  sensitive   = true
}

output "operator_kubeconfig" {
  description = "Ephemeral kubeconfig snippet derived from the provided token."
  value       = local.operator_kubeconfig
  sensitive   = true
}
