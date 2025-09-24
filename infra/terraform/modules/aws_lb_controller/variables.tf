variable "enabled" {
  description = "Whether to render the AWS Load Balancer Controller resources."
  type        = bool
  default     = true
}

variable "cluster_name" {
  description = "Name of the EKS cluster the controller should target."
  type        = string
}

variable "cluster_region" {
  description = "AWS region hosting the EKS cluster."
  type        = string
}

variable "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL exposed by the EKS cluster for IRSA."
  type        = string
}

variable "vpc_id" {
  description = "Identifier of the VPC associated with the cluster."
  type        = string
  default     = null
}

variable "private_subnet_ids" {
  description = "Private subnet identifiers used for internal load balancers."
  type        = list(string)
  default     = []
}

variable "public_subnet_ids" {
  description = "Public subnet identifiers used for internet-facing load balancers."
  type        = list(string)
  default     = []
}

variable "namespace" {
  description = "Namespace in which to install the controller Helm release."
  type        = string
  default     = "kube-system"
}

variable "release_name" {
  description = "Helm release name for the AWS Load Balancer Controller."
  type        = string
  default     = "aws-load-balancer-controller"
}

variable "chart_repository" {
  description = "Helm repository hosting the AWS Load Balancer Controller chart."
  type        = string
  default     = "https://aws.github.io/eks-charts"
}

variable "chart_version" {
  description = "Version of the AWS Load Balancer Controller chart to deploy."
  type        = string
  default     = "1.9.2"
}

variable "chart_name" {
  description = "Name of the chart within the repository."
  type        = string
  default     = "aws-load-balancer-controller"
}

variable "create_namespace" {
  description = "Allow Helm to create the namespace if it does not exist."
  type        = bool
  default     = false
}

variable "service_account" {
  description = "Overrides for the controller service account."
  type = object({
    name        = optional(string)
    create      = optional(bool)
    annotations = optional(map(string))
  })
  default = {}
}

variable "iam_role_name" {
  description = "Explicit name for the controller IAM role."
  type        = string
  default     = null
}

variable "additional_policy_arns" {
  description = "Additional IAM policy ARNs attached to the controller role."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to IAM resources created by the module."
  type        = map(string)
  default     = {}
}

variable "helm_additional_values" {
  description = "Additional Helm value documents appended to the controller release."
  type        = list(any)
  default     = []
}

variable "helm_timeout_seconds" {
  description = "Timeout in seconds for the Helm installation or upgrade."
  type        = number
  default     = 300
}

variable "load_balancer_scheme" {
  description = "Scheme used by the default ALB (internal or internet-facing)."
  type        = string
  default     = "internal"

  validation {
    condition     = contains(["internal", "internet-facing"], lower(var.load_balancer_scheme))
    error_message = "load_balancer_scheme must be either 'internal' or 'internet-facing'."
  }
}

variable "load_balancer_ip_address_type" {
  description = "IP address allocation strategy for the ALB."
  type        = string
  default     = "ipv4"

  validation {
    condition     = contains(["ipv4", "dualstack"], lower(var.load_balancer_ip_address_type))
    error_message = "load_balancer_ip_address_type must be 'ipv4' or 'dualstack'."
  }
}

variable "target_type" {
  description = "Target type registered behind the ALB (instance or ip)."
  type        = string
  default     = "ip"

  validation {
    condition     = contains(["ip", "instance"], lower(var.target_type))
    error_message = "target_type must be either 'ip' or 'instance'."
  }
}

variable "ingress_class_name" {
  description = "Name assigned to the default IngressClass managed by the controller."
  type        = string
  default     = "alb"
}

variable "ingress_class_params_name" {
  description = "Name assigned to the IngressClassParams resource managed by the controller."
  type        = string
  default     = null
}

variable "set_default_ingress_class" {
  description = "Mark the controller-managed ingress class as the cluster default."
  type        = bool
  default     = true
}

variable "load_balancer_certificate_arn" {
  description = "ARN of the ACM certificate bound to HTTPS listeners."
  type        = string
  default     = null
}

variable "enable_shield_advanced" {
  description = "Annotate managed ingresses so AWS Shield Advanced protects the resulting ALBs."
  type        = bool
  default     = false
}

variable "waf_web_acl_arn" {
  description = "Associate a managed AWS WAF web ACL with controller-managed ALBs."
  type        = string
  default     = null
}

variable "load_balancer_ssl_policy" {
  description = "SSL policy enforced on HTTPS listeners."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "load_balancer_additional_annotations" {
  description = "Custom annotations merged into the default ingress annotation set."
  type        = map(string)
  default     = {}
}

variable "load_balancer_additional_tags" {
  description = "Tags applied to load balancers created by the controller via IngressClassParams."
  type        = map(string)
  default     = {}
}

variable "load_balancer_security_group_ids" {
  description = "Security groups attached to load balancers provisioned by this controller."
  type        = list(string)
  default     = []
}

variable "node_selector" {
  description = "Node selector applied to the controller deployment."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations applied to the controller deployment."
  type = list(object({
    key               = optional(string)
    operator          = optional(string)
    value             = optional(string)
    effect            = optional(string)
    toleration_seconds = optional(number)
  }))
  default = []
}
