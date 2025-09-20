output "enabled" {
  description = "Whether the observability module is active."
  value       = local.enabled
}

output "mode" {
  description = "Selected observability deployment mode."
  value       = var.mode
}

output "medusa_extra_values" {
  description = "Helm value fragments that should be merged into the Medusa release."
  value       = local.medusa_extra_values
}

output "grafana_admin_secret" {
  description = "Reference to the secret housing Grafana administrative credentials."
  value = {
    name      = local.grafana_admin_secret_name
    namespace = local.grafana_admin_secret_namespace
  }
  sensitive = true
}

output "kube_prometheus_release" {
  description = "Metadata about the kube-prometheus-stack release when deployed."
  value = local.deploy_kube_stack ? {
    name      = var.release_name
    namespace = var.namespace
  } : null
}
