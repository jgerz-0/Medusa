variable "cluster_name" {
  description = "Logical name of the Kubernetes cluster hosting Medusa."
  type        = string
}

variable "cluster_endpoint" {
  description = "EKS API server endpoint used to reach the cluster."
  type        = string
}

variable "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate authority data for the Kubernetes API server."
  type        = string
}

variable "cluster_token" {
  description = "Bearer token for authenticating to the Kubernetes API."
  type        = string
  sensitive   = true
}

variable "namespace" {
  description = "Namespace where the Medusa release should be installed."
  type        = string
}

variable "release_name" {
  description = "Helm release name for the Medusa deployment."
  type        = string
}

variable "secret_name" {
  description = "Name of the Kubernetes secret consumed by the chart."
  type        = string
  default     = "medusa-secrets"
}

variable "secret_strategy" {
  description = "Secret delivery strategy for the chart (inline, externalSecret, or sealedSecret)."
  type        = string

  validation {
    condition     = contains(["inline", "externalSecret", "sealedSecret"], var.secret_strategy)
    error_message = "secret_strategy must be one of 'inline', 'externalSecret', or 'sealedSecret'."
  }
}

variable "manage_inline_secret" {
  description = "Whether Terraform should provision the inline Kubernetes secret instead of Helm."
  type        = bool
  default     = false

  validation {
    condition     = (!var.manage_inline_secret) || var.secret_strategy == "inline"
    error_message = "manage_inline_secret can only be enabled when secret_strategy is 'inline'."
  }
}

variable "manage_external_secret" {
  description = "Whether Terraform should render the ExternalSecret manifest instead of Helm."
  type        = bool
  default     = false

  validation {
    condition     = (!var.manage_external_secret) || var.secret_strategy == "externalSecret"
    error_message = "manage_external_secret can only be enabled when secret_strategy is 'externalSecret'."
  }
}

variable "manage_sealed_secret" {
  description = "Whether Terraform should render the SealedSecret manifest instead of Helm."
  type        = bool
  default     = false

  validation {
    condition     = (!var.manage_sealed_secret) || var.secret_strategy == "sealedSecret"
    error_message = "manage_sealed_secret can only be enabled when secret_strategy is 'sealedSecret'."
  }
}

variable "database" {
  description = "Database connection attributes sourced from the RDS module outputs."
  type = object({
    hostname          = string
    port              = number
    database          = string
    connection_string = string
    secret_arn        = string
    secret_name       = string
  })
}

variable "bucket_names" {
  description = "Mapping of logical usage to S3 bucket names (artifact, fuzzing, metadata)."
  type        = map(string)

  validation {
    condition     = contains(keys(var.bucket_names), "artifact")
    error_message = "bucket_names must include at least the 'artifact' bucket."
  }
}

variable "callback_tokens" {
  description = "Callback tokens for Medusa agents keyed by capability (nuclei, sqlmap, enrichment, binary_static, binary_symbolic, binary_fuzzing, zap, validator)."
  type        = map(string)

  validation {
    condition     = alltrue([for key in ["nuclei", "sqlmap", "enrichment", "binary_static", "binary_symbolic", "binary_fuzzing", "zap", "validator"] : contains(keys(var.callback_tokens), key)])
    error_message = "callback_tokens must provide nuclei, sqlmap, enrichment, binary_static, binary_symbolic, binary_fuzzing, zap, and validator entries."
  }
}

variable "inline_secret_overrides" {
  description = "Additional key/value pairs merged into the inline secret payload."
  type        = map(string)
  default     = {}
}

variable "external_secret_configuration" {
  description = "Configuration for the ExternalSecret strategy when enabled."
  type = object({
    secret_store_kind = string
    secret_store_name = string
    refresh_interval  = optional(string)
    data = optional(list(object({
      secretKey = string
      remoteRef = map(string)
    })))
    data_from = optional(list(object({
      extract = object({
        key = string
      })
    })))
    target_template = optional(object({
      type           = optional(string)
      engine_version = optional(string)
      data           = optional(map(string))
      metadata       = optional(map(string))
    }))
  })
  default = null

  validation {
    condition     = var.secret_strategy != "externalSecret" || var.external_secret_configuration != null
    error_message = "external_secret_configuration must be provided when secret_strategy is 'externalSecret'."
  }
}

variable "sealed_secret_configuration" {
  description = "Configuration for the SealedSecret strategy when enabled."
  type = object({
    encrypted_data       = map(string)
    metadata_annotations = optional(map(string))
    metadata_labels      = optional(map(string))
    template_annotations = optional(map(string))
    template_labels      = optional(map(string))
    template_type        = optional(string)
  })
  default = null

  validation {
    condition = var.secret_strategy != "sealedSecret" || (
      var.sealed_secret_configuration != null
      && length(var.sealed_secret_configuration.encrypted_data) > 0
    )
    error_message = "sealed_secret_configuration with at least one encrypted_data entry is required when secret_strategy is 'sealedSecret'."
  }
}

variable "controller_additional_env" {
  description = "Additional environment variables injected into the controller deployment."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "controller_ingress_security" {
  description = "Controls AWS WAF and Shield integration for the controller ingress."
  type = object({
    shield_enabled = optional(bool)
    waf = optional(object({
      enabled     = optional(bool)
      web_acl_arn = optional(string)
      fail_open   = optional(bool)
    }))
  })
  default = {}
}

variable "extra_values" {
  description = "Additional Helm value documents appended to the release."
  type        = list(any)
  default     = []
}

variable "common_labels" {
  description = "Standardised labels applied to managed Kubernetes resources."
  type        = map(string)
  default     = {}
}

variable "namespace_pod_security_standards" {
  description = "Pod Security Standards levels enforced on the Medusa namespace via labels."
  type = object({
    enforce = string
    audit   = string
    warn    = string
  })
  default = {
    enforce = "restricted"
    audit   = "restricted"
    warn    = "restricted"
  }
}

variable "render_operator_kubeconfig" {
  description = "Whether to render a kubeconfig snippet for operators using the supplied token."
  type        = bool
  default     = false
}

variable "helm_timeout_seconds" {
  description = "Timeout (in seconds) for Helm release operations."
  type        = number
  default     = 600
}
