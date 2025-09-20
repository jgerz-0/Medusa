output "enabled" {
  description = "Whether the IRSA resources were rendered."
  value       = var.enabled && local.controller_output != null
}

output "controller" {
  description = "Controller IRSA context including role identifiers and Helm overrides."
  value       = local.controller_output
}

output "workers" {
  description = "Worker IRSA contexts keyed by worker identifier."
  value       = local.worker_outputs
}

output "helm_values" {
  description = "Helm value documents that annotate Medusa service accounts with IRSA roles."
  value       = local.helm_values
}
