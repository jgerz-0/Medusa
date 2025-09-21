variable "vpc_name" {
  description = "Optional override for the VPC name. Defaults to <cluster_name>-vpc when unset."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "Primary CIDR block assigned to the VPC hosting the Medusa EKS control plane."
  type        = string
}

variable "availability_zones" {
  description = "Availability zones to spread subnets and node groups across for resilience."
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "CIDR ranges dedicated to private subnets where EKS nodes run."
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "CIDR ranges for public subnets that expose load balancers and NAT gateways."
  type        = list(string)
}

variable "cluster_name" {
  description = "Name of the EKS cluster to provision."
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version enforced for the EKS control plane."
  type        = string
  default     = "1.29"
}

variable "cluster_endpoint_public_access" {
  description = "Expose the Kubernetes API endpoint over the public internet."
  type        = bool
  default     = false
}

variable "cluster_endpoint_private_access" {
  description = "Enable private access to the Kubernetes API endpoint over the VPC network."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of allowed CIDR ranges when public API access is enabled."
  type        = list(string)
  default     = []
}

variable "cluster_log_types" {
  description = "EKS control plane log types shipped to CloudWatch for auditing."
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
  description = "Retention period for EKS control plane logs stored in CloudWatch."
  type        = number
  default     = 30
}

variable "cluster_iam_role_name" {
  description = "Optional fixed name for the EKS control plane IAM role."
  type        = string
  default     = null
}

variable "cluster_iam_role_additional_policy_arns" {
  description = "Additional managed policy ARNs attached to the EKS control plane IAM role."
  type        = map(string)
  default     = {}
}

variable "node_iam_role_name" {
  description = "Optional fixed name for the managed node group IAM role."
  type        = string
  default     = null
}

variable "node_iam_role_additional_policy_arns" {
  description = "Managed policy ARNs shared across all managed node group IAM roles."
  type        = map(string)
  default     = {}
}

variable "default_node_group_disk_size" {
  description = "Baseline disk size (GiB) applied to managed node groups when a value is not provided."
  type        = number
  default     = 50
}

variable "managed_node_groups" {
  description = "Declarative definition of managed node groups backing the Medusa workloads."
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

variable "tags" {
  description = "Base tags propagated to every AWS resource for traceability."
  type        = map(string)
  default     = {}
}
