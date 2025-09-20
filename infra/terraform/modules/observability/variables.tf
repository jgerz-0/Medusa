variable "enabled" {
  description = "Toggle for deploying any observability components."
  type        = bool
  default     = false
}

variable "mode" {
  description = "Observability deployment strategy: embedded (Medusa chart dependencies) or kube-prometheus-stack."
  type        = string
  default     = "embedded"

  validation {
    condition     = contains(["embedded", "kube-prometheus-stack"], var.mode)
    error_message = "mode must be either 'embedded' or 'kube-prometheus-stack'."
  }
}

variable "namespace" {
  description = "Namespace housing the kube-prometheus-stack release when mode is kube-prometheus-stack."
  type        = string
  default     = "observability"
}

variable "create_namespace" {
  description = "Allow Terraform to manage the namespace for the kube-prometheus-stack installation."
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Helm release name for the kube-prometheus-stack deployment."
  type        = string
  default     = "kube-prometheus-stack"
}

variable "chart_repository" {
  description = "Helm repository hosting kube-prometheus-stack."
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
}

variable "chart_name" {
  description = "Helm chart name for the Prometheus stack."
  type        = string
  default     = "kube-prometheus-stack"
}

variable "chart_version" {
  description = "Helm chart version for kube-prometheus-stack."
  type        = string
  default     = "55.8.2"
}

variable "helm_timeout_seconds" {
  description = "Timeout (in seconds) for the kube-prometheus-stack Helm release."
  type        = number
  default     = 900
}

variable "medusa_namespace" {
  description = "Namespace where the Medusa chart is installed. Used for embedding and ServiceMonitor scoping."
  type        = string
}

variable "medusa_release_name" {
  description = "Name of the Medusa Helm release for labelling ServiceMonitor resources."
  type        = string
}

variable "service_monitor_labels" {
  description = "Additional labels injected into the Medusa ServiceMonitor resource."
  type        = map(string)
  default     = {}
}

variable "service_monitor_interval" {
  description = "Override for the ServiceMonitor scrape interval. Leave null to use chart defaults."
  type        = string
  default     = null
}

variable "service_monitor_scrape_timeout" {
  description = "Override for the ServiceMonitor scrape timeout. Leave null to use chart defaults."
  type        = string
  default     = null
}

variable "embedded_service_monitor_enabled" {
  description = "Whether to render the Medusa ServiceMonitor when mode is embedded (requires the CRD to exist)."
  type        = bool
  default     = false
}

variable "prometheus_retention" {
  description = "Retention window for Prometheus metrics."
  type        = string
  default     = "15d"
}

variable "embedded_prometheus_persistent_volume_enabled" {
  description = "Enable persistence for the embedded Prometheus server."
  type        = bool
  default     = true
}

variable "embedded_prometheus_storage_class" {
  description = "StorageClass for the embedded Prometheus volume."
  type        = string
  default     = ""
}

variable "embedded_prometheus_storage_size" {
  description = "Persistent volume size for the embedded Prometheus server."
  type        = string
  default     = "20Gi"
}

variable "embedded_prometheus_service_type" {
  description = "Service type exposed by the embedded Prometheus server."
  type        = string
  default     = "ClusterIP"
}

variable "grafana_service_type" {
  description = "Kubernetes service type used for Grafana."
  type        = string
  default     = "ClusterIP"
}

variable "grafana_ingress_enabled" {
  description = "Expose Grafana via ingress."
  type        = bool
  default     = false
}

variable "grafana_ingress_class_name" {
  description = "Ingress class used for Grafana when enabled."
  type        = string
  default     = null
}

variable "grafana_ingress_annotations" {
  description = "Additional annotations applied to the Grafana ingress resource."
  type        = map(string)
  default     = {}
}

variable "grafana_ingress_hosts" {
  description = "Hosts and paths routed to the Grafana ingress."
  type = list(object({
    host  = string
    paths = list(object({
      path      = string
      path_type = optional(string)
    }))
  }))
  default = []
}

variable "grafana_ingress_tls" {
  description = "TLS configuration for the Grafana ingress."
  type = list(object({
    secret_name = string
    hosts       = list(string)
  }))
  default = []
}

variable "grafana_ingress_additional_settings" {
  description = "Raw map merged into the Grafana ingress stanza for advanced controls (e.g., custom backend protocols)."
  type        = map(any)
  default     = {}
}

variable "manage_grafana_admin_secret" {
  description = "Have Terraform manage the Grafana admin secret. Disable to reference an externally managed secret."
  type        = bool
  default     = false
}

variable "grafana_admin_secret_name" {
  description = "Name of the secret that stores Grafana admin credentials."
  type        = string
  default     = "grafana-admin-credentials"
}

variable "grafana_admin_user_key" {
  description = "Key within the Grafana admin secret containing the username."
  type        = string
  default     = "admin-user"
}

variable "grafana_admin_password_key" {
  description = "Key within the Grafana admin secret containing the password."
  type        = string
  default     = "admin-password"
}

variable "grafana_admin_secret_labels" {
  description = "Additional labels applied to the Grafana admin secret when managed by Terraform."
  type        = map(string)
  default     = {}
}

variable "grafana_admin_secret_annotations" {
  description = "Annotations applied to the managed Grafana admin secret."
  type        = map(string)
  default     = {}
}

variable "grafana_admin_credentials" {
  description = "Grafana admin username and password when Terraform manages the secret."
  type = object({
    username = string
    password = string
  })
  default = null

  validation {
    condition     = (!var.manage_grafana_admin_secret) || var.grafana_admin_credentials != null
    error_message = "grafana_admin_credentials must be supplied when manage_grafana_admin_secret is true."
  }
}

variable "enable_alertmanager" {
  description = "Deploy Alertmanager alongside the kube-prometheus-stack release."
  type        = bool
  default     = false
}

variable "alertmanager_config" {
  description = "Inline Alertmanager configuration for routing alerts to external systems."
  type        = string
  default     = null
}

variable "alertmanager_additional_values" {
  description = "Additional map merged into the Alertmanager Helm values when enabled."
  type        = map(any)
  default     = {}
}

variable "kube_prometheus_additional_values" {
  description = "Additional Helm value documents appended to the kube-prometheus-stack release."
  type        = list(any)
  default     = []
}

variable "embedded_additional_values" {
  description = "Additional Helm value documents appended to Medusa when mode is embedded."
  type        = list(any)
  default     = []
}

variable "external_stack_medusa_overrides" {
  description = "Additional Medusa Helm values applied when kube-prometheus-stack is selected."
  type        = list(any)
  default     = []
}

variable "common_labels" {
  description = "Standard labels applied to managed Kubernetes objects."
  type        = map(string)
  default     = {}
}
