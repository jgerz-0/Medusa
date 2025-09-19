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
