output "enabled" {
  description = "Whether the AWS Load Balancer Controller release was rendered."
  value       = local.enabled
}

output "role_arn" {
  description = "IAM role ARN assumed by the controller service account."
  value       = local.enabled ? aws_iam_role.controller[0].arn : null
}

output "service_account_name" {
  description = "Service account name used by the controller Helm release."
  value       = local.service_account_name
}

output "service_account_annotations" {
  description = "Annotations applied to the controller service account."
  value       = local.enabled ? local.service_account_annotations_effective : local.service_account_annotations
}

output "ingress_class_name" {
  description = "Ingress class name advertised by the controller."
  value       = local.ingress_class_name
}

output "ingress_annotations" {
  description = "Default annotations applied to Medusa ingresses targeting the ALB."
  value       = local.enabled ? local.ingress_annotations : {}
}

output "ingress_class_params_name" {
  description = "Name of the IngressClassParams resource managed by the Helm release."
  value       = local.ingress_class_params_name
}

output "helm_release_name" {
  description = "Name of the Helm release managing the controller."
  value       = local.enabled ? helm_release.controller[0].name : null
}
