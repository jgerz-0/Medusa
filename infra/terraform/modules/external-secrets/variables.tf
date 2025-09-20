variable "enabled" {
  description = "Toggle for deploying the External Secrets Operator and related resources."
  type        = bool
  default     = false
}

variable "namespace" {
  description = "Namespace where the External Secrets Operator release should reside."
  type        = string
  default     = "external-secrets"
}

variable "release_name" {
  description = "Helm release name for the External Secrets Operator."
  type        = string
  default     = "external-secrets"
}

variable "chart_repository" {
  description = "Helm repository hosting the External Secrets Operator chart."
  type        = string
  default     = "https://charts.external-secrets.io"
}

variable "chart_name" {
  description = "Name of the External Secrets Operator Helm chart."
  type        = string
  default     = "external-secrets"
}

variable "chart_version" {
  description = "Chart version to deploy."
  type        = string
  default     = "0.9.13"
}

variable "create_namespace" {
  description = "Allow Helm to create the operator namespace when it does not already exist."
  type        = bool
  default     = true
}

variable "install_crds" {
  description = "Install the External Secrets custom resource definitions via Helm."
  type        = bool
  default     = true
}

variable "service_account_create" {
  description = "Create the operator service account via Helm."
  type        = bool
  default     = true
}

variable "service_account_name" {
  description = "Name of the operator service account."
  type        = string
  default     = "external-secrets-operator"
}

variable "service_account_annotations" {
  description = "Additional annotations merged into the operator service account."
  type        = map(string)
  default     = {}
}

variable "irsa_role_arn" {
  description = "IAM role ARN wired through IRSA for External Secrets to access AWS Secrets Manager."
  type        = string
  default     = null

  validation {
    condition     = (!var.enabled) || (var.irsa_role_arn != null && var.irsa_role_arn != "")
    error_message = "irsa_role_arn must be provided when the External Secrets Operator is enabled."
  }
}

variable "cluster_name" {
  description = "Logical name of the EKS cluster hosting the operator."
  type        = string
}

variable "aws_region" {
  description = "AWS region for the backing Secrets Manager instance."
  type        = string
}

variable "secret_store_name" {
  description = "Name assigned to the SecretStore or ClusterSecretStore resource."
  type        = string
  default     = "medusa-cluster-secrets"
}

variable "secret_store_scope" {
  description = "Scope of the generated secret store (cluster or namespace)."
  type        = string
  default     = "cluster"

  validation {
    condition     = contains(["cluster", "namespace"], var.secret_store_scope)
    error_message = "secret_store_scope must be either 'cluster' or 'namespace'."
  }
}

variable "secret_store_annotations" {
  description = "Annotations applied to the SecretStore/ClusterSecretStore metadata."
  type        = map(string)
  default     = {}
}

variable "rds_master_secret_arn" {
  description = "AWS Secrets Manager ARN containing the Medusa controller database credentials."
  type        = string
  default     = null
}

variable "default_refresh_interval" {
  description = "Default refresh interval applied to managed ExternalSecrets."
  type        = string
  default     = "1h"
}

variable "external_secrets" {
  description = "Optional ExternalSecret manifests to render in addition to the Medusa configuration."
  type = map(object({
    name              = optional(string)
    namespace         = string
    secret_store_name = optional(string)
    secret_store_kind = optional(string)
    refresh_interval  = optional(string)
    labels            = optional(map(string))
    annotations       = optional(map(string))
    target = optional(object({
      name            = optional(string)
      creation_policy = optional(string)
      deletion_policy = optional(string)
      template        = optional(map(any))
    }))
    data = optional(list(object({
      secret_key = string
      remote_ref = object({
        key      = string
        property = optional(string)
        version  = optional(string)
      })
    })))
    data_from = optional(list(object({
      extract = object({
        key = string
      })
    })))
  }))
  default = {}
}

variable "additional_helm_values" {
  description = "Extra Helm values applied to the operator release."
  type        = list(any)
  default     = []
}

variable "helm_timeout_seconds" {
  description = "Timeout (in seconds) for Helm operations."
  type        = number
  default     = 600
}

variable "common_labels" {
  description = "Common labels injected into Kubernetes resources managed by this module."
  type        = map(string)
  default     = {}
}
