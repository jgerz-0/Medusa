output "enabled" {
  description = "Whether the External Secrets Operator module is managing resources."
  value       = var.enabled
}

output "secret_store_name" {
  description = "Name of the managed SecretStore/ClusterSecretStore."
  value       = var.enabled ? var.secret_store_name : null
}

output "secret_store_kind" {
  description = "Kind of the managed secret store resource."
  value       = var.enabled ? local.secret_store_kind : null
}

output "service_account_name" {
  description = "Service account bound to the operator release."
  value       = var.enabled ? var.service_account_name : null
}

output "medusa_database_remote_refs" {
  description = "Remote ref definitions for projecting the Medusa database credentials via ExternalSecret."
  value       = var.enabled ? local.medusa_database_remote_refs : []
}
