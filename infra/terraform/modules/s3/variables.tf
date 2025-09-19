variable "project_name" {
  description = "Base project identifier used when deriving bucket names."
  type        = string
}

variable "environment" {
  description = "Environment suffix appended to derived bucket names."
  type        = string
}

variable "artifact_bucket_name" {
  description = "Explicit S3 bucket name override for artifacts."
  type        = string
  default     = null
}

variable "artifact_bucket_prefix" {
  description = "Prefix combined with the environment to form the artifact bucket name when an explicit name is not supplied."
  type        = string
  default     = null
}

variable "artifact_bucket_suffix" {
  description = "Suffix appended to the project/environment name to derive the artifact bucket name when overrides are not provided."
  type        = string
  default     = "artifacts"
}

variable "force_destroy" {
  description = "Force bucket destruction even if objects remain. Enable only for ephemeral environments."
  type        = bool
  default     = false
}

variable "versioning_enabled" {
  description = "Toggle S3 versioning for the artifact bucket."
  type        = bool
  default     = true
}

variable "enable_artifact_expiration" {
  description = "Whether to expire current object versions after the configured retention period."
  type        = bool
  default     = true
}

variable "artifact_retention_days" {
  description = "Number of days to retain current object versions when expiration is enabled."
  type        = number
  default     = 365

  validation {
    condition     = var.artifact_retention_days > 0
    error_message = "artifact_retention_days must be greater than zero."
  }
}

variable "enable_noncurrent_version_expiration" {
  description = "Whether to purge noncurrent object versions after the configured retention period."
  type        = bool
  default     = true
}

variable "noncurrent_version_retention_days" {
  description = "Number of days to retain noncurrent object versions when expiration is enabled."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_retention_days > 0
    error_message = "noncurrent_version_retention_days must be greater than zero."
  }
}

variable "abort_incomplete_multipart_upload_days" {
  description = "Number of days after initiation to abort incomplete multipart uploads. Set to null to disable."
  type        = number
  default     = 7
}

variable "worker_access" {
  description = "Map of worker identifiers to the S3 key prefix they are allowed to manage."
  type = map(object({
    prefix       = string
    allow_delete = optional(bool, true)
  }))
  default = {}

  validation {
    condition     = length(var.worker_access) == 0 || alltrue([for cfg in var.worker_access : regexreplace(trimspace(cfg.prefix), "^/+", "") != ""])
    error_message = "Worker prefixes must be non-empty strings."
  }
}

variable "tags" {
  description = "Tags applied to S3 and KMS resources."
  type        = map(string)
  default     = {}
}

variable "create_kms_key" {
  description = "Whether to provision a dedicated KMS key for the artifact bucket."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Existing KMS key ARN used for server-side encryption when create_kms_key is false."
  type        = string
  default     = null

  validation {
    condition     = var.create_kms_key || var.kms_key_arn != null
    error_message = "Either supply an existing kms_key_arn or enable create_kms_key."
  }
}

variable "kms_key_alias" {
  description = "Alias assigned to the managed KMS key when created by this module."
  type        = string
  default     = null
}

variable "kms_key_deletion_window_in_days" {
  description = "Waiting period before a scheduled KMS key deletion executes."
  type        = number
  default     = 30
}
