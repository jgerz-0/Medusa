variable "enabled" {
  description = "Toggle creation of IAM roles and Helm overrides for Medusa IRSA bindings."
  type        = bool
  default     = true
}

variable "namespace" {
  description = "Kubernetes namespace hosting the Medusa release."
  type        = string
}

variable "release_name" {
  description = "Helm release name used for computing deterministic service account names."
  type        = string
}

variable "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL exposed by the EKS cluster for IRSA."
  type        = string
}

variable "controller_policy_document" {
  description = "IAM policy document granting the Medusa controller access to AWS services (JSON)."
  type        = string
}

variable "worker_policy_documents" {
  description = "IAM policy documents keyed by worker identifier used for fine-grained IRSA roles."
  type        = map(string)
  default     = {}
}

variable "controller_service_account" {
  description = "Optional overrides for the controller service account and role naming."
  type = object({
    name        = optional(string)
    create      = optional(bool)
    role_name   = optional(string)
    annotations = optional(map(string))
  })
  default = {}
}

variable "worker_service_accounts" {
  description = "Optional overrides for worker service accounts. Keys must match worker_policy_documents."
  type = map(object({
    helm_worker_key      = optional(string)
    service_account_name = optional(string)
    role_name            = optional(string)
    create               = optional(bool)
    enabled              = optional(bool)
    annotations          = optional(map(string))
  }))
  default = {}
}

variable "tags" {
  description = "Tags applied to IAM roles for traceability."
  type        = map(string)
  default     = {}
}
