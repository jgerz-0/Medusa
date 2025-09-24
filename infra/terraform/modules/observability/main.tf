locals {
  enabled           = var.enabled
  deploy_kube_stack = var.enabled && var.mode == "kube-prometheus-stack"
  use_embedded      = var.enabled && var.mode == "embedded"

  grafana_admin_secret_name      = var.grafana_admin_secret_name
  grafana_admin_secret_namespace = local.deploy_kube_stack ? var.namespace : var.medusa_namespace
  grafana_admin_secret_labels    = merge(
    var.common_labels,
    {
      "app.kubernetes.io/name"      = "grafana-admin-credentials",
      "app.kubernetes.io/component" = "observability",
    },
    var.grafana_admin_secret_labels,
  )
  grafana_admin_secret_annotations = merge(
    {
      "medusa.security/description" = "Grafana admin credentials managed via Terraform. Rotate frequently.",
    },
    var.grafana_admin_secret_annotations,
  )

  grafana_ingress_hosts = [
    for host in var.grafana_ingress_hosts : {
      host  = host.host
      paths = [
        for path in host.paths : {
          path     = path.path
          pathType = coalesce(path.path_type, "Prefix")
        }
      ]
    }
  ]

  grafana_ingress_tls = [
    for tls in var.grafana_ingress_tls : {
      secretName = tls.secret_name
      hosts      = tls.hosts
    }
  ]

  grafana_ingress_values = var.grafana_ingress_enabled ? merge(
    { enabled = true },
    var.grafana_ingress_class_name != null ? { ingressClassName = var.grafana_ingress_class_name } : {},
    var.grafana_ingress_annotations != {} ? { annotations = var.grafana_ingress_annotations } : {},
    length(local.grafana_ingress_hosts) > 0 ? { hosts = local.grafana_ingress_hosts } : {},
    length(local.grafana_ingress_tls) > 0 ? { tls = local.grafana_ingress_tls } : {},
    var.grafana_ingress_additional_settings,
  ) : {}

  grafana_admin_username = var.manage_grafana_admin_secret ? var.grafana_admin_credentials.username : ""
  grafana_admin_password = var.manage_grafana_admin_secret ? var.grafana_admin_credentials.password : ""

  service_monitor_labels_effective = local.deploy_kube_stack
    ? merge({ release = var.release_name }, var.service_monitor_labels)
    : var.service_monitor_labels

  service_monitor_enabled = local.deploy_kube_stack || (local.use_embedded && var.embedded_service_monitor_enabled)
  service_monitor_settings = merge(
    { enabled = local.service_monitor_enabled },
    length(local.service_monitor_labels_effective) > 0 ? { labels = local.service_monitor_labels_effective } : {},
    var.service_monitor_interval != null ? { interval = var.service_monitor_interval } : {},
    var.service_monitor_scrape_timeout != null ? { scrapeTimeout = var.service_monitor_scrape_timeout } : {},
  )

  alertmanager_template_files = {
    for template in fileset("${path.module}/templates", "*.tmpl") :
    basename(template) => file("${path.module}/templates/${template}")
  }

  grafana_dashboard_json = local.deploy_kube_stack ? templatefile(
    "${path.module}/templates/grafana-medusa-controller-dashboard.json.tftpl",
    {}
  ) : null

  slo_rule_manifest = local.deploy_kube_stack ? templatefile(
    "${path.module}/templates/prometheus-medusa-slo-rules.yaml.tftpl",
    {
      namespace = var.namespace
    }
  ) : null

  medusa_embedded_values = local.use_embedded ? merge(
    {
      metrics = {
        prometheus = merge(
          {
            enabled       = true
            serviceMonitor = local.service_monitor_settings
          },
          {},
        )
        grafana = {
          enabled = true
        }
      }
      grafana = merge(
        {
          admin = {
            existingSecret = local.grafana_admin_secret_name
            userKey        = var.grafana_admin_user_key
            passwordKey    = var.grafana_admin_password_key
          }
          service = {
            type = var.grafana_service_type
          }
          networkPolicy = {
            enabled       = true
            allowExternal = false
          }
        },
        local.grafana_ingress_values != {} ? { ingress = local.grafana_ingress_values } : {},
      )
      prometheus = {
        server = {
          retention = var.prometheus_retention
          service = {
            type = var.embedded_prometheus_service_type
          }
          persistentVolume = {
            enabled      = var.embedded_prometheus_persistent_volume_enabled
            size         = var.embedded_prometheus_storage_size
            storageClass = var.embedded_prometheus_storage_class
          }
        }
      }
    },
    {},
  ) : null

  medusa_external_values = local.deploy_kube_stack ? merge(
    {
      metrics = {
        prometheus = merge(
          {
            enabled       = true
            serviceMonitor = local.service_monitor_settings
          },
          {},
        )
        grafana = {
          enabled = false
        }
      }
      prometheus = {
        server = {
          enabled = false
        }
        alertmanager = {
          enabled = false
        }
        pushgateway = {
          enabled = false
        }
        kubeStateMetrics = {
          enabled = false
        }
        nodeExporter = {
          enabled = false
        }
      }
    },
    {},
  ) : null

  medusa_extra_values = !local.enabled ? [] : (
    local.use_embedded
    ? concat(
      local.medusa_embedded_values != null ? [local.medusa_embedded_values] : [],
      var.embedded_additional_values,
    )
    : local.deploy_kube_stack
    ? concat(
      local.medusa_external_values != null ? [local.medusa_external_values] : [],
      var.external_stack_medusa_overrides,
    )
    : []
  )

  kube_prometheus_base_values = !local.deploy_kube_stack ? {} : merge(
    {
      fullnameOverride   = var.release_name
      namespaceOverride  = var.namespace
      cleanPrometheusOperatorCRDs = false
      kubeProxy = {
        enabled = false
      }
      grafana = merge(
        {
          admin = {
            existingSecret = local.grafana_admin_secret_name
            userKey        = var.grafana_admin_user_key
            passwordKey    = var.grafana_admin_password_key
          }
          service = {
            type = var.grafana_service_type
          }
          networkPolicy = {
            enabled       = true
            allowExternal = false
          }
        },
        local.grafana_ingress_values != {} ? { ingress = local.grafana_ingress_values } : {},
      )
      prometheus = {
        prometheusSpec = merge(
          {
            retention                                = var.prometheus_retention
            serviceMonitorNamespaceSelector          = {
              matchNames = [var.medusa_namespace]
            }
            serviceMonitorSelector                   = {
              matchLabels = local.service_monitor_labels_effective
            }
            serviceMonitorSelectorNilUsesHelmValues  = false
            serviceMonitorNamespaceSelectorNilUsesHelmValues = false
            podMonitorSelectorNilUsesHelmValues      = false
            probeSelectorNilUsesHelmValues           = false
            enableAdminAPI                           = false
          },
          {},
        )
      }
      prometheusOperator = {
        manageCrds = true
        networkPolicy = {
          enabled = true
        }
        admissionWebhooks = {
          enabled = true
          patch = {
            enabled = true
          }
        }
      }
      "kube-state-metrics" = {
        networkPolicy = {
          enabled = true
        }
      }
      "prometheus-node-exporter" = {
        networkPolicy = {
          enabled = true
        }
      }
    },
    var.enable_alertmanager ? {
      alertmanager = merge(
        {
          enabled = true
          alertmanagerSpec = {
            replicas = 2
          }
        },
        var.alertmanager_config != null ? { config = var.alertmanager_config } : {},
        length(local.alertmanager_template_files) > 0 ? { templateFiles = local.alertmanager_template_files } : {},
        var.alertmanager_additional_values,
      )
    } : {
      alertmanager = {
        enabled = false
      }
    },
  )

  kube_prometheus_values = local.deploy_kube_stack
    ? concat(
      [yamlencode(local.kube_prometheus_base_values)],
      [for value in var.kube_prometheus_additional_values : yamlencode(value)],
    )
    : []
}

resource "kubernetes_namespace" "observability" {
  count = local.deploy_kube_stack && var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = merge(
      var.common_labels,
      {
        "medusa.security/scope" = "observability"
      },
    )
  }
}

resource "kubernetes_secret" "grafana_admin" {
  count = local.enabled && var.manage_grafana_admin_secret ? 1 : 0

  metadata {
    name      = local.grafana_admin_secret_name
    namespace = local.grafana_admin_secret_namespace
    labels    = local.grafana_admin_secret_labels
    annotations = local.grafana_admin_secret_annotations
  }

  data = {
    (var.grafana_admin_user_key)     = base64encode(local.grafana_admin_username)
    (var.grafana_admin_password_key) = base64encode(local.grafana_admin_password)
  }

  type = "Opaque"
}

resource "helm_release" "kube_prometheus_stack" {
  count = local.deploy_kube_stack ? 1 : 0

  name       = var.release_name
  namespace  = var.namespace
  repository = var.chart_repository
  chart      = var.chart_name
  version    = var.chart_version

  create_namespace = false
  atomic           = true
  cleanup_on_fail  = true
  dependency_update = true
  wait             = true
  timeout          = var.helm_timeout_seconds

  values = local.kube_prometheus_values

  depends_on = concat(
    var.create_namespace ? [kubernetes_namespace.observability[0]] : [],
    var.manage_grafana_admin_secret ? [kubernetes_secret.grafana_admin[0]] : [],
  )
}

resource "kubernetes_config_map" "medusa_grafana_dashboards" {
  count = local.deploy_kube_stack && local.grafana_dashboard_json != null ? 1 : 0

  metadata {
    name      = "medusa-grafana-dashboards"
    namespace = var.namespace
    labels = merge(
      var.common_labels,
      {
        "app.kubernetes.io/name"      = "medusa-grafana-dashboards",
        "app.kubernetes.io/component" = "observability",
        "grafana_dashboard"           = "1",
      },
    )
    annotations = {
      grafana_folder                  = "Medusa"
      "medusa.security/description" = "Controller and worker SLO dashboards managed by Terraform."
    }
  }

  data = {
    "medusa-controller.json" = local.grafana_dashboard_json
  }

  depends_on = [helm_release.kube_prometheus_stack]
}

resource "kubernetes_manifest" "medusa_slo_alerts" {
  count = local.deploy_kube_stack && local.slo_rule_manifest != null ? 1 : 0

  manifest = yamldecode(local.slo_rule_manifest)

  depends_on = [helm_release.kube_prometheus_stack]
}
