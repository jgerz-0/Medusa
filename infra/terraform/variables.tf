variable "project_name" {
  description = "Logical name for the Medusa deployment."
  type        = string
  default     = null
}

variable "environment" {
  description = "Deployment environment identifier (e.g., dev, prod)."
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region to deploy infrastructure into."
  type        = string
  default     = null
}

variable "aws_profile" {
  description = "Named AWS CLI profile supplying credentials for Terraform."
  type        = string
  default     = null
}

variable "cluster_name" {
  description = "Explicit Kubernetes cluster name override."
  type        = string
  default     = null
}

variable "state_bucket" {
  description = "S3 bucket for Terraform remote state."
  type        = string
  default     = null
}

variable "state_dynamodb_table" {
  description = "DynamoDB table used for Terraform state locking."
  type        = string
  default     = null
}

variable "state_key_prefix" {
  description = "Prefix appended to the remote state key path."
  type        = string
  default     = null
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file used for Kubernetes authentication."
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Optional kubeconfig context override."
  type        = string
  default     = null
}

variable "helm_registry_config" {
  description = "Path to the Docker config.json containing Helm OCI registry credentials."
  type        = string
  default     = "~/.docker/config.json"
}

variable "container_registry_server" {
  description = "Container registry host for pushing Medusa images."
  type        = string
  default     = "ghcr.io"
}

variable "container_registry_username" {
  description = "Username for authenticating to the container registry."
  type        = string
  default     = "medusa-ci"
}

variable "container_registry_password" {
  description = "Password or token for the container registry. Use short-lived credentials in practice."
  type        = string
  default     = "REPLACE_ME"
  sensitive   = true
}

variable "helm_repository_url" {
  description = "OCI Helm repository that stores Medusa charts."
  type        = string
  default     = "oci://ghcr.io/medusa/charts"
}

variable "helm_repository_username" {
  description = "Username for pulling Helm charts."
  type        = string
  default     = "medusa-ci"
}

variable "helm_repository_password" {
  description = "Password or token for pulling Helm charts. Use short-lived credentials in practice."
  type        = string
  default     = "REPLACE_ME"
  sensitive   = true
}

variable "enable_external_secrets_operator" {
  description = "Deploy the External Secrets Operator and supporting resources."
  type        = bool
  default     = false
}

variable "external_secrets_namespace" {
  description = "Namespace hosting the External Secrets Operator release."
  type        = string
  default     = "external-secrets"
}

variable "external_secrets_release_name" {
  description = "Helm release name for the External Secrets Operator."
  type        = string
  default     = "external-secrets"
}

variable "external_secrets_chart_version" {
  description = "Version of the External Secrets Operator chart to deploy."
  type        = string
  default     = "0.9.13"
}

variable "external_secrets_create_namespace" {
  description = "Allow Helm to create the operator namespace if missing."
  type        = bool
  default     = true
}

variable "external_secrets_install_crds" {
  description = "Install the External Secrets custom resource definitions via Helm."
  type        = bool
  default     = true
}

variable "external_secrets_service_account_name" {
  description = "Service account name used by the External Secrets Operator."
  type        = string
  default     = "external-secrets-operator"
}

variable "external_secrets_service_account_annotations" {
  description = "Additional annotations merged into the operator service account."
  type        = map(string)
  default     = {}
}

variable "external_secrets_irsa_role_arn" {
  description = "IAM role ARN assumed by the External Secrets Operator service account."
  type        = string
  default     = null
}

variable "external_secrets_secret_store_name" {
  description = "Name of the SecretStore or ClusterSecretStore resource for External Secrets."
  type        = string
  default     = "medusa-cluster-secrets"
}

variable "external_secrets_secret_store_scope" {
  description = "Scope of the External Secrets store (cluster or namespace)."
  type        = string
  default     = "cluster"

  validation {
    condition     = contains(["cluster", "namespace"], var.external_secrets_secret_store_scope)
    error_message = "external_secrets_secret_store_scope must be either 'cluster' or 'namespace'."
  }
}

variable "external_secrets_secret_store_annotations" {
  description = "Annotations applied to the SecretStore/ClusterSecretStore metadata."
  type        = map(string)
  default     = {}
}

variable "external_secrets_default_refresh_interval" {
  description = "Default refresh interval applied to managed ExternalSecrets."
  type        = string
  default     = "1h"
}

variable "external_secrets_external_secrets" {
  description = "Optional ExternalSecret manifests rendered by the External Secrets module."
  type        = map(object({
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

variable "external_secrets_additional_helm_values" {
  description = "Additional Helm value documents merged into the operator release."
  type        = list(any)
  default     = []
}

variable "external_secrets_helm_timeout_seconds" {
  description = "Timeout (in seconds) for External Secrets Helm operations."
  type        = number
  default     = 600
}

variable "external_secrets_additional_labels" {
  description = "Additional labels injected into External Secrets resources."
  type        = map(string)
  default     = {}
}

variable "external_secrets_medusa_refresh_interval" {
  description = "Refresh interval applied to the Medusa ExternalSecret when the operator is enabled."
  type        = string
  default     = "5m"
}

variable "medusa_secret_strategy" {
  description = "Secret delivery strategy for the Medusa Helm release (inline or externalSecret)."
  type        = string
  default     = "inline"

  validation {
    condition     = contains(["inline", "externalSecret"], var.medusa_secret_strategy)
    error_message = "medusa_secret_strategy must be either 'inline' or 'externalSecret'."
  }
}

variable "medusa_secret_name" {
  description = "Name of the Kubernetes secret referenced by the Medusa chart."
  type        = string
  default     = "medusa-secrets"
}

variable "medusa_manage_inline_secret" {
  description = "Allow Terraform to create the inline secret instead of Helm when using inline strategy."
  type        = bool
  default     = false
}

variable "medusa_manage_external_secret" {
  description = "Allow Terraform to create the ExternalSecret manifest when using externalSecret strategy."
  type        = bool
  default     = false
}

variable "medusa_inline_secret_overrides" {
  description = "Additional key/value pairs merged into the Medusa inline secret."
  type        = map(string)
  default     = {}
}

variable "medusa_external_secret_configuration" {
  description = "ExternalSecret configuration passed to the Medusa module when using externalSecret strategy."
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
    condition     = var.medusa_secret_strategy != "externalSecret" || var.medusa_external_secret_configuration != null
    error_message = "medusa_external_secret_configuration must be provided when medusa_secret_strategy is 'externalSecret'."
  }
}

variable "medusa_controller_additional_env" {
  description = "Additional environment variables injected into the Medusa controller deployment."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "medusa_extra_values" {
  description = "Extra Helm value documents appended to the Medusa release."
  type        = list(any)
  default     = []
}

variable "enable_medusa_irsa" {
  description = "Enable creation of IAM Roles for Service Accounts (IRSA) for the Medusa controller and workers."
  type        = bool
  default     = false
}

variable "medusa_irsa_controller_service_account" {
  description = "Optional overrides for the controller service account and IAM role naming when IRSA is enabled."
  type = object({
    name        = optional(string)
    create      = optional(bool)
    role_name   = optional(string)
    annotations = optional(map(string))
  })
  default = {}
}

variable "medusa_irsa_worker_service_accounts" {
  description = "Overrides for worker service accounts used when rendering IRSA roles. Keys should match the artifact worker identifiers."
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

variable "medusa_bucket_overrides" {
  description = "Optional overrides for Medusa bucket mappings (artifact, fuzzing, metadata)."
  type        = map(string)
  default     = {}
}

variable "medusa_additional_labels" {
  description = "Extra Kubernetes labels merged into Medusa-managed resources."
  type        = map(string)
  default     = {}
}

variable "medusa_render_operator_kubeconfig" {
  description = "Render a kubeconfig snippet for the Medusa cluster in module outputs."
  type        = bool
  default     = false
}

variable "medusa_helm_timeout_seconds" {
  description = "Timeout (in seconds) for the Medusa Helm release operations."
  type        = number
  default     = 600
}

variable "vpc_cidr" {
  description = "Primary CIDR range used for the Medusa EKS VPC."
  type        = string
}

variable "availability_zones" {
  description = "Availability zones leveraged for the cluster subnets."
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks reserved for private subnets hosting worker nodes."
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks used by public subnets for ingress and NAT."
  type        = list(string)
}

variable "cluster_version" {
  description = "Desired Kubernetes control plane version."
  type        = string
  default     = "1.29"
}

variable "cluster_endpoint_public_access" {
  description = "Whether to expose the Kubernetes API endpoint publicly."
  type        = bool
  default     = false
}

variable "cluster_endpoint_private_access" {
  description = "Whether to enable private Kubernetes API access inside the VPC."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR ranges allowed to reach the public Kubernetes API endpoint."
  type        = list(string)
  default     = []
}

variable "cluster_log_types" {
  description = "Control plane log types shipped to CloudWatch for auditing."
  type        = list(string)
  default     = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]
}

variable "cloudwatch_log_retention_in_days" {
  description = "Retention period for Kubernetes control plane logs stored in CloudWatch."
  type        = number
  default     = 30
}

variable "cluster_iam_role_name" {
  description = "Optional fixed name for the EKS control plane IAM role."
  type        = string
  default     = null
}

variable "cluster_iam_role_additional_policy_arns" {
  description = "Additional managed policy ARNs attached to the cluster IAM role."
  type        = map(string)
  default     = {}
}

variable "node_iam_role_name" {
  description = "Optional fixed name for the managed node IAM role."
  type        = string
  default     = null
}

variable "node_iam_role_additional_policy_arns" {
  description = "Managed policy ARNs applied to every managed node IAM role."
  type        = map(string)
  default     = {}
}

variable "default_node_group_disk_size" {
  description = "Baseline disk size (GiB) when node group overrides are omitted."
  type        = number
  default     = 50
}

variable "managed_node_groups" {
  description = "Declarative definition of managed node groups for the Medusa workloads."
  type = map(
    object({
      desired_size = number
      max_size     = number
      min_size     = number
      instance_types = list(string)
      capacity_type  = optional(string)
      disk_size      = optional(number)
      labels         = optional(map(string))
      taints = optional(
        list(
          object({
            key    = string
            value  = string
            effect = string
          })
        )
      )
      subnet_ids             = optional(list(string))
      additional_policy_arns = optional(map(string))
      tags                   = optional(map(string))
    })
  )
  default = {}
}

variable "artifact_bucket_name" {
  description = "Explicit S3 bucket name for storing scan artifacts. When null, a deterministic name is derived."
  type        = string
  default     = null
}

variable "artifact_bucket_prefix" {
  description = "Prefix combined with the environment when deriving the artifact bucket name."
  type        = string
  default     = null
}

variable "artifact_bucket_suffix" {
  description = "Suffix appended to the derived artifact bucket name when overrides are omitted."
  type        = string
  default     = "artifacts"
}

variable "artifact_bucket_force_destroy" {
  description = "Force bucket deletion even when objects remain. Use only for non-production environments."
  type        = bool
  default     = false
}

variable "artifact_bucket_versioning_enabled" {
  description = "Toggle S3 versioning on the artifact bucket."
  type        = bool
  default     = true
}

variable "artifact_enable_expiration" {
  description = "Whether to expire current object versions after the configured retention window."
  type        = bool
  default     = true
}

variable "artifact_retention_days" {
  description = "Retention period in days for current object versions."
  type        = number
  default     = 365
}

variable "artifact_enable_noncurrent_version_expiration" {
  description = "Whether to purge noncurrent object versions after the configured retention window."
  type        = bool
  default     = true
}

variable "artifact_noncurrent_version_retention_days" {
  description = "Retention period in days for noncurrent object versions."
  type        = number
  default     = 90
}

variable "artifact_abort_incomplete_multipart_upload_days" {
  description = "Days after initiation before incomplete multipart uploads are aborted. Set to null to disable."
  type        = number
  default     = 7
}

variable "artifact_worker_prefixes" {
  description = "Map of Medusa worker identifiers to the S3 prefixes they manage."
  type = map(object({
    prefix       = string
    allow_delete = optional(bool, true)
  }))
  default = {
    nuclei = {
      prefix       = "nuclei/"
      allow_delete = true
    }
    binary_preprocess = {
      prefix       = "preprocess/metadata/"
      allow_delete = true
    }
    binary_static_analysis = {
      prefix       = "analysis/reports/"
      allow_delete = true
    }
    binary_fuzzing = {
      prefix       = "analysis/fuzzing/"
      allow_delete = true
    }
  }
}

variable "artifact_create_kms_key" {
  description = "Whether to create a dedicated KMS key for artifact encryption."
  type        = bool
  default     = true
}

variable "artifact_kms_key_arn" {
  description = "Existing KMS key ARN to reuse for artifact encryption."
  type        = string
  default     = null
}

variable "artifact_kms_key_alias" {
  description = "Alias assigned when the module provisions the artifact KMS key."
  type        = string
  default     = null
}

variable "artifact_kms_deletion_window_in_days" {
  description = "Waiting period in days before a scheduled KMS key deletion executes."
  type        = number
  default     = 30
}

variable "rds_database_name" {
  description = "Primary database name provisioned for the Medusa controller."
  type        = string
  default     = "medusadb"
}

variable "rds_instance_identifier" {
  description = "Optional explicit identifier for the controller database instance."
  type        = string
  default     = null
}

variable "rds_instance_class" {
  description = "Instance class assigned to the controller database."
  type        = string
  default     = "db.t3.medium"
}

variable "rds_engine" {
  description = "Database engine backing the controller datastore."
  type        = string
  default     = "postgres"
}

variable "rds_engine_version" {
  description = "Engine version pinned for deterministic behaviour."
  type        = string
  default     = "15.4"
}

variable "rds_port" {
  description = "Network port exposed by the controller database."
  type        = number
  default     = 5432
}

variable "rds_allocated_storage" {
  description = "Initial storage (GiB) allocated to the controller database."
  type        = number
  default     = 50
}

variable "rds_max_allocated_storage" {
  description = "Maximum storage (GiB) permitted for autoscaling."
  type        = number
  default     = 200
}

variable "rds_master_username" {
  description = "Master username used by the controller for database access."
  type        = string
  default     = "medusa_admin"
}

variable "rds_master_secret_name" {
  description = "Optional override for the master credentials secret name."
  type        = string
  default     = null
}

variable "rds_master_secret_description" {
  description = "Optional description for the master credentials secret."
  type        = string
  default     = null
}

variable "rds_kms_key_arn" {
  description = "Customer managed KMS key encrypting the controller database."
  type        = string
  default     = null
}

variable "rds_master_secret_kms_key_arn" {
  description = "KMS key encrypting the controller database master credentials secret."
  type        = string
  default     = null
}

variable "rds_backup_retention_period" {
  description = "Number of days to retain automated database backups."
  type        = number
  default     = 7
}

variable "rds_preferred_backup_window" {
  description = "Optional UTC window for automated backups."
  type        = string
  default     = null
}

variable "rds_preferred_maintenance_window" {
  description = "Optional UTC window for database maintenance."
  type        = string
  default     = null
}

variable "rds_multi_az" {
  description = "Enable Multi-AZ deployment for the controller database."
  type        = bool
  default     = false
}

variable "rds_deletion_protection" {
  description = "Protect the controller database from accidental deletion."
  type        = bool
  default     = true
}

variable "rds_skip_final_snapshot" {
  description = "Skip the final snapshot when destroying the controller database."
  type        = bool
  default     = false
}

variable "rds_apply_immediately" {
  description = "Apply database modifications immediately rather than waiting for the maintenance window."
  type        = bool
  default     = false
}

variable "rds_monitoring_interval" {
  description = "Enhanced monitoring interval in seconds for the database (0 disables)."
  type        = number
  default     = 0
}

variable "rds_iam_authentication_enabled" {
  description = "Enable IAM authentication for the controller database."
  type        = bool
  default     = false
}

variable "rds_performance_insights_enabled" {
  description = "Toggle Performance Insights for the controller database."
  type        = bool
  default     = true
}

variable "rds_performance_insights_kms_key_arn" {
  description = "KMS key securing Performance Insights data for the database."
  type        = string
  default     = null
}

variable "rds_master_secret_rotation_enabled" {
  description = "Enable automatic rotation of the controller master credentials secret."
  type        = bool
  default     = false
}

variable "rds_master_secret_rotation_lambda_arn" {
  description = "Rotation Lambda handling credential updates when rotation is enabled."
  type        = string
  default     = null
}

variable "rds_master_secret_rotation_automatically_after_days" {
  description = "Rotation cadence in days for the controller master credentials secret."
  type        = number
  default     = 30
}
