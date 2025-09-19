variable "database_name" {
  description = "Name of the primary database to provision for the Medusa controller."
  type        = string
}

variable "instance_class" {
  description = "Instance class balancing performance and cost for the RDS instance."
  type        = string
}

variable "allocated_storage" {
  description = "Initial storage (GiB) allocated to the database."
  type        = number
}

variable "max_allocated_storage" {
  description = "Upper bound (GiB) for storage autoscaling. Defaults to allocated_storage when omitted."
  type        = number
  default     = null

  validation {
    condition     = var.max_allocated_storage == null || var.max_allocated_storage >= var.allocated_storage
    error_message = "max_allocated_storage must be greater than or equal to allocated_storage."
  }
}

variable "engine" {
  description = "Database engine used for the controller (postgres recommended)."
  type        = string
  default     = "postgres"
}

variable "engine_version" {
  description = "Specific database engine version to enforce for deterministic behaviour."
  type        = string
  default     = "15.4"
}

variable "port" {
  description = "TCP port exposed by the database."
  type        = number
  default     = 5432
}

variable "instance_identifier" {
  description = "Optional explicit DB identifier. Defaults to the database name."
  type        = string
  default     = null
}

variable "vpc_id" {
  description = "VPC hosting the Medusa workloads and the backing database."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs used by the RDS subnet group."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "At least one subnet ID must be supplied for the RDS subnet group."
  }
}

variable "allowed_security_group_ids" {
  description = "Security group IDs granted ingress to the database (typically EKS worker groups)."
  type        = list(string)

  validation {
    condition     = length(var.allowed_security_group_ids) > 0
    error_message = "Provide at least one security group ID to authorize database access."
  }
}

variable "master_username" {
  description = "Master username stored in Secrets Manager for the controller."
  type        = string
  default     = "medusa_admin"
}

variable "master_secret_name" {
  description = "Optional name override for the master credentials secret."
  type        = string
  default     = null
}

variable "master_secret_description" {
  description = "Optional description override for the master credentials secret."
  type        = string
  default     = null
}

variable "kms_key_arn" {
  description = "Customer managed KMS key encrypting the database storage."
  type        = string
  default     = null
}

variable "master_secret_kms_key_arn" {
  description = "Customer managed KMS key encrypting the master credentials secret."
  type        = string
  default     = null
}

variable "backup_retention_period" {
  description = "Number of days to retain automated backups."
  type        = number
  default     = 7
}

variable "preferred_backup_window" {
  description = "Optional backup window (UTC) for predictable snapshots."
  type        = string
  default     = null
}

variable "preferred_maintenance_window" {
  description = "Optional maintenance window (UTC) for patching."
  type        = string
  default     = null
}

variable "multi_az" {
  description = "Whether to deploy a Multi-AZ standby for high availability."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Prevents accidental destruction of the production datastore."
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "If true, skips creating a final snapshot when the instance is destroyed."
  type        = bool
  default     = false
}

variable "apply_immediately" {
  description = "Apply modifications immediately rather than waiting for the maintenance window."
  type        = bool
  default     = false
}

variable "monitoring_interval" {
  description = "Enhanced monitoring interval in seconds (0 disables it)."
  type        = number
  default     = 0
}

variable "iam_database_authentication_enabled" {
  description = "Enable IAM token-based authentication for break-glass access."
  type        = bool
  default     = false
}

variable "performance_insights_enabled" {
  description = "Toggle Performance Insights for query diagnostics."
  type        = bool
  default     = true
}

variable "performance_insights_kms_key_arn" {
  description = "KMS key securing Performance Insights data."
  type        = string
  default     = null
}

variable "master_secret_rotation_enabled" {
  description = "Enable automatic rotation for the master credentials secret."
  type        = bool
  default     = false
}

variable "master_secret_rotation_lambda_arn" {
  description = "Lambda ARN handling credential rotation when enabled."
  type        = string
  default     = null
}

variable "master_secret_rotation_automatically_after_days" {
  description = "Rotation cadence in days for the master credentials secret."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Common tags propagated to every RDS resource."
  type        = map(string)
  default     = {}
}
