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
