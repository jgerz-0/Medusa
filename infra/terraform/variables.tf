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

variable "enable_observability" {
  description = "Deploy Prometheus/Grafana observability tooling alongside Medusa."
  type        = bool
  default     = false
}

variable "observability_mode" {
  description = "Select between the kube-prometheus-stack or the Medusa chart's embedded Prometheus/Grafana."
  type        = string
  default     = "embedded"

  validation {
    condition     = contains(["embedded", "kube-prometheus-stack"], var.observability_mode)
    error_message = "observability_mode must be either 'embedded' or 'kube-prometheus-stack'."
  }
}

variable "observability_namespace" {
  description = "Namespace hosting the kube-prometheus-stack release when enabled."
  type        = string
  default     = "observability"
}

variable "observability_create_namespace" {
  description = "Allow Terraform to manage the observability namespace."
  type        = bool
  default     = true
}

variable "observability_release_name" {
  description = "Helm release name for the kube-prometheus-stack deployment."
  type        = string
  default     = "kube-prometheus-stack"
}

variable "observability_chart_repository" {
  description = "Helm repository hosting kube-prometheus-stack."
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
}

variable "observability_chart_name" {
  description = "Name of the Helm chart used for the observability stack."
  type        = string
  default     = "kube-prometheus-stack"
}

variable "observability_chart_version" {
  description = "Version of the kube-prometheus-stack chart to deploy."
  type        = string
  default     = "55.8.2"
}

variable "observability_helm_timeout_seconds" {
  description = "Timeout (in seconds) for observability Helm operations."
  type        = number
  default     = 900
}

variable "observability_service_monitor_labels" {
  description = "Extra labels applied to the Medusa ServiceMonitor when metrics are enabled."
  type        = map(string)
  default     = {}
}

variable "observability_service_monitor_interval" {
  description = "Override for the ServiceMonitor scrape interval."
  type        = string
  default     = null
}

variable "observability_service_monitor_scrape_timeout" {
  description = "Override for the ServiceMonitor scrape timeout."
  type        = string
  default     = null
}

variable "observability_embedded_service_monitor_enabled" {
  description = "Render the ServiceMonitor when using embedded observability (requires pre-installed CRDs)."
  type        = bool
  default     = false
}

variable "observability_prometheus_retention" {
  description = "Retention window for Prometheus metrics."
  type        = string
  default     = "15d"
}

variable "observability_embedded_prometheus_persistent_volume_enabled" {
  description = "Enable persistence for the embedded Prometheus server."
  type        = bool
  default     = true
}

variable "observability_embedded_prometheus_storage_class" {
  description = "StorageClass assigned to the embedded Prometheus volume."
  type        = string
  default     = ""
}

variable "observability_embedded_prometheus_storage_size" {
  description = "Persistent volume size for the embedded Prometheus server."
  type        = string
  default     = "20Gi"
}

variable "observability_embedded_prometheus_service_type" {
  description = "Service type used by the embedded Prometheus server."
  type        = string
  default     = "ClusterIP"
}

variable "observability_grafana_service_type" {
  description = "Service type used to expose Grafana."
  type        = string
  default     = "ClusterIP"
}

variable "observability_grafana_ingress_enabled" {
  description = "Expose Grafana via an ingress resource."
  type        = bool
  default     = false
}

variable "observability_grafana_ingress_class_name" {
  description = "Ingress class used for Grafana when ingress is enabled."
  type        = string
  default     = null
}

variable "observability_grafana_ingress_annotations" {
  description = "Annotations merged into the Grafana ingress."
  type        = map(string)
  default     = {}
}

variable "observability_grafana_ingress_hosts" {
  description = "Hosts routed to Grafana when ingress is enabled."
  type = list(object({
    host  = string
    paths = list(object({
      path      = string
      path_type = optional(string)
    }))
  }))
  default = []
}

variable "observability_grafana_ingress_tls" {
  description = "TLS configuration for the Grafana ingress."
  type = list(object({
    secret_name = string
    hosts       = list(string)
  }))
  default = []
}

variable "observability_grafana_ingress_additional_settings" {
  description = "Raw map merged into the Grafana ingress stanza for advanced controls."
  type        = map(any)
  default     = {}
}

variable "observability_manage_grafana_admin_secret" {
  description = "Have Terraform manage the Grafana admin credentials secret."
  type        = bool
  default     = false
}

variable "observability_grafana_admin_secret_name" {
  description = "Name of the secret containing Grafana admin credentials."
  type        = string
  default     = "grafana-admin-credentials"
}

variable "observability_grafana_admin_user_key" {
  description = "Key storing the Grafana admin username in the secret."
  type        = string
  default     = "admin-user"
}

variable "observability_grafana_admin_password_key" {
  description = "Key storing the Grafana admin password in the secret."
  type        = string
  default     = "admin-password"
}

variable "observability_grafana_admin_secret_labels" {
  description = "Additional labels for the managed Grafana admin secret."
  type        = map(string)
  default     = {}
}

variable "observability_grafana_admin_secret_annotations" {
  description = "Annotations applied to the managed Grafana admin secret."
  type        = map(string)
  default     = {}
}

variable "observability_grafana_admin_credentials" {
  description = "Grafana admin username and password when Terraform manages the secret."
  type = object({
    username = string
    password = string
  })
  default = null

  validation {
    condition     = (!var.observability_manage_grafana_admin_secret) || var.observability_grafana_admin_credentials != null
    error_message = "observability_grafana_admin_credentials must be provided when managing the Grafana admin secret."
  }
}

variable "observability_enable_alertmanager" {
  description = "Deploy Alertmanager as part of the observability stack."
  type        = bool
  default     = false
}

variable "observability_alertmanager_config" {
  description = "Inline Alertmanager configuration for routing alerts."
  type        = string
  default     = null
}

variable "observability_alertmanager_template_settings" {
  description = "Inputs for rendering the bundled Alertmanager configuration template. Provide when secrets are sourced via External Secrets."
  type = object({
    default_receiver = string
    pagerduty = optional(object({
      receiver         = string
      secret_name      = string
      secret_key       = string
      severity_label   = optional(string)
      class            = optional(string)
      component        = optional(string)
      group            = optional(string)
      summary_template = optional(string)
    }))
    slack = optional(object({
      receiver       = string
      secret_name    = string
      secret_key     = string
      channel        = string
      username       = optional(string)
      icon_emoji     = optional(string)
      send_resolved  = optional(bool)
      footer         = optional(string)
      title_template = optional(string)
      body_template  = optional(string)
    }))
    additional_routes = optional(list(object({
      receiver = string
      continue = optional(bool)
      matchers = optional(list(object({
        name  = string
        value = string
        regex = optional(bool)
      })))
    })))
  })
  default = null
}

variable "observability_alertmanager_additional_values" {
  description = "Additional map merged into the Alertmanager Helm values."
  type        = map(any)
  default     = {}
}

variable "observability_kube_prometheus_additional_values" {
  description = "Additional Helm value documents for the kube-prometheus-stack release."
  type        = list(any)
  default     = []
}

variable "observability_embedded_additional_values" {
  description = "Additional Helm value documents merged into Medusa when using embedded observability."
  type        = list(any)
  default     = []
}

variable "observability_external_stack_medusa_overrides" {
  description = "Extra Medusa Helm values applied when relying on kube-prometheus-stack."
  type        = list(any)
  default     = []
}

variable "observability_additional_labels" {
  description = "Additional labels applied to observability resources managed by Terraform."
  type        = map(string)
  default     = {}
}

variable "enable_aws_lb_controller" {
  description = "Deploy the AWS Load Balancer Controller Helm chart and supporting IAM role."
  type        = bool
  default     = false
}

variable "aws_lb_controller_namespace" {
  description = "Namespace hosting the AWS Load Balancer Controller release."
  type        = string
  default     = "kube-system"
}

variable "aws_lb_controller_release_name" {
  description = "Helm release name for the AWS Load Balancer Controller."
  type        = string
  default     = "aws-load-balancer-controller"
}

variable "aws_lb_controller_chart_repository" {
  description = "Helm repository that publishes the AWS Load Balancer Controller chart."
  type        = string
  default     = "https://aws.github.io/eks-charts"
}

variable "aws_lb_controller_chart_name" {
  description = "Chart name for the AWS Load Balancer Controller."
  type        = string
  default     = "aws-load-balancer-controller"
}

variable "aws_lb_controller_chart_version" {
  description = "Version of the AWS Load Balancer Controller chart to deploy."
  type        = string
  default     = "1.9.2"
}

variable "aws_lb_controller_create_namespace" {
  description = "Allow Helm to create the controller namespace if it is missing."
  type        = bool
  default     = false
}

variable "aws_lb_controller_service_account" {
  description = "Optional overrides for the controller service account."
  type = object({
    name        = optional(string)
    create      = optional(bool)
    annotations = optional(map(string))
  })
  default = {}
}

variable "aws_lb_controller_iam_role_name" {
  description = "Explicit name assigned to the controller IAM role."
  type        = string
  default     = null
}

variable "aws_lb_controller_additional_policy_arns" {
  description = "Additional IAM policies attached to the controller role."
  type        = list(string)
  default     = []
}

variable "aws_lb_controller_additional_helm_values" {
  description = "Extra Helm value documents applied to the controller release."
  type        = list(any)
  default     = []
}

variable "aws_lb_controller_helm_timeout_seconds" {
  description = "Timeout (in seconds) for AWS Load Balancer Controller Helm operations."
  type        = number
  default     = 600
}

variable "aws_lb_controller_scheme" {
  description = "Scheme assigned to the default Application Load Balancer (internal or internet-facing)."
  type        = string
  default     = "internal"

  validation {
    condition     = contains(["internal", "internet-facing"], lower(var.aws_lb_controller_scheme))
    error_message = "aws_lb_controller_scheme must be either 'internal' or 'internet-facing'."
  }
}

variable "aws_lb_controller_ip_address_type" {
  description = "IP address allocation strategy for the controller-managed load balancer."
  type        = string
  default     = "ipv4"

  validation {
    condition     = contains(["ipv4", "dualstack"], lower(var.aws_lb_controller_ip_address_type))
    error_message = "aws_lb_controller_ip_address_type must be 'ipv4' or 'dualstack'."
  }
}

variable "aws_lb_controller_target_type" {
  description = "Target registration mode for ALB target groups (ip or instance)."
  type        = string
  default     = "ip"

  validation {
    condition     = contains(["ip", "instance"], lower(var.aws_lb_controller_target_type))
    error_message = "aws_lb_controller_target_type must be either 'ip' or 'instance'."
  }
}

variable "aws_lb_controller_ingress_class_name" {
  description = "IngressClass name advertised by the AWS Load Balancer Controller."
  type        = string
  default     = "alb"
}

variable "aws_lb_controller_ingress_class_params_name" {
  description = "IngressClassParams name managed by the controller release."
  type        = string
  default     = null
}

variable "aws_lb_controller_set_default_ingress_class" {
  description = "Mark the controller-managed IngressClass as the cluster default."
  type        = bool
  default     = true
}

variable "aws_lb_controller_certificate_arn" {
  description = "ACM certificate ARN bound to HTTPS listeners created by the controller."
  type        = string
  default     = null
}

variable "aws_lb_controller_enable_shield_advanced" {
  description = "Enable AWS Shield Advanced protection on controller-managed ALBs."
  type        = bool
  default     = false
}

variable "aws_lb_controller_waf_web_acl_arn" {
  description = "AWS WAF web ACL ARN associated with controller-managed ALBs."
  type        = string
  default     = null
}

variable "aws_lb_controller_ssl_policy" {
  description = "SSL policy enforced on controller-managed HTTPS listeners."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "aws_lb_controller_additional_annotations" {
  description = "Custom annotations merged into default ingress settings produced by the controller module."
  type        = map(string)
  default     = {}
}

variable "aws_lb_controller_additional_tags" {
  description = "Tags applied to load balancers created via the controller's IngressClassParams."
  type        = map(string)
  default     = {}
}

variable "aws_lb_controller_security_group_ids" {
  description = "Security group identifiers attached to load balancers created by the controller."
  type        = list(string)
  default     = []
}

variable "aws_lb_controller_node_selector" {
  description = "Node selector applied to the controller deployment."
  type        = map(string)
  default     = {}
}

variable "aws_lb_controller_tolerations" {
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

variable "medusa_secret_strategy" {
  description = "Secret delivery strategy for the Medusa Helm release (inline, externalSecret, or sealedSecret)."
  type        = string
  default     = "inline"

  validation {
    condition     = contains(["inline", "externalSecret", "sealedSecret"], var.medusa_secret_strategy)
    error_message = "medusa_secret_strategy must be one of 'inline', 'externalSecret', or 'sealedSecret'."
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

variable "medusa_manage_sealed_secret" {
  description = "Allow Terraform to create the SealedSecret manifest when using sealedSecret strategy."
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

variable "medusa_sealed_secret_configuration" {
  description = "SealedSecret configuration passed to the Medusa module when using sealedSecret strategy."
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
    condition = var.medusa_secret_strategy != "sealedSecret" || (
      var.medusa_sealed_secret_configuration != null
      && length(var.medusa_sealed_secret_configuration.encrypted_data) > 0
    )
    error_message = "medusa_sealed_secret_configuration with at least one encrypted_data entry is required when medusa_secret_strategy is 'sealedSecret'."
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

variable "medusa_controller_ingress_enabled" {
  description = "Enable the Medusa controller Ingress resource and pass ALB annotations."
  type        = bool
  default     = false
}

variable "medusa_controller_ingress_class_name" {
  description = "Override the ingressClassName applied to the Medusa controller ingress."
  type        = string
  default     = null
}

variable "medusa_controller_ingress_additional_annotations" {
  description = "Custom annotations merged into the controller ingress before rendering."
  type        = map(string)
  default     = {}
}

variable "medusa_controller_shield_enabled" {
  description = "Enable AWS Shield Advanced protection on the controller ingress ALB."
  type        = bool
  default     = false
}

variable "medusa_controller_waf_enabled" {
  description = "Associate an AWS WAFv2 web ACL with the controller ingress ALB."
  type        = bool
  default     = false
}

variable "medusa_controller_waf_acl_arn" {
  description = "ARN of the AWS WAFv2 web ACL to bind when WAF protection is enabled."
  type        = string
  default     = null
}

variable "medusa_controller_waf_fail_open" {
  description = "Allow the ALB to fail open when the WAF service is unavailable (defaults to fail closed)."
  type        = bool
  default     = false
}

variable "medusa_controller_ingress_hosts" {
  description = "Host and path configuration for the Medusa controller ingress."
  type = list(object({
    host  = string
    paths = list(object({
      path      = string
      path_type = optional(string)
    }))
  }))
  default = []
}

variable "medusa_controller_ingress_tls" {
  description = "TLS secrets referenced by the Medusa controller ingress."
  type = list(object({
    hosts       = list(string)
    secret_name = string
  }))
  default = []
}

variable "medusa_controller_ingress_extra_settings" {
  description = "Raw map of additional ingress settings merged into the Helm values."
  type        = map(any)
  default     = {}
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
    binary_symbolic_execution = {
      prefix       = "analysis/symbolic/"
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
