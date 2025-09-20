terraform {
  required_version = ">= 1.5.7"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
  }
}

locals {
  operator_enabled = var.enabled

  service_account_annotations = merge(
    var.service_account_annotations,
    var.irsa_role_arn != null ? { "eks.amazonaws.com/role-arn" = var.irsa_role_arn } : {},
  )

  base_helm_values = {
    installCRDs = var.install_crds
    serviceAccount = {
      create      = var.service_account_create
      name        = var.service_account_name
      annotations = local.service_account_annotations
    }
  }

  rendered_helm_values = concat(
    [yamlencode(local.base_helm_values)],
    [for value in var.additional_helm_values : yamlencode(value)],
  )

  secret_store_kind = var.secret_store_scope == "cluster" ? "ClusterSecretStore" : "SecretStore"

  secret_store_metadata = merge(
    {
      name   = var.secret_store_name
      labels = merge(
        var.common_labels,
        {
          "medusa.security/cluster"   = var.cluster_name,
          "medusa.security/component" = "external-secrets-store",
        },
      )
      annotations = var.secret_store_annotations
    },
    var.secret_store_scope == "namespace" ? { namespace = var.namespace } : {},
  )

  secret_store_manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = local.secret_store_kind
    metadata   = local.secret_store_metadata
    spec = {
      provider = {
        aws = {
          service = "SecretsManager"
          region  = var.aws_region
          auth = {
            jwt = {
              serviceAccountRef = {
                name      = var.service_account_name
                namespace = var.namespace
              }
            }
          }
        }
      }
    }
  }

  medusa_database_remote_refs = var.rds_master_secret_arn != null ? [
    {
      secretKey = "medusaDatabaseUsername"
      remoteRef = {
        key      = var.rds_master_secret_arn
        property = "username"
      }
    },
    {
      secretKey = "medusaDatabasePassword"
      remoteRef = {
        key      = var.rds_master_secret_arn
        property = "password"
      }
    },
  ] : []

  managed_external_secrets = var.enabled ? {
    for key, cfg in var.external_secrets :
    key => {
      apiVersion = "external-secrets.io/v1beta1"
      kind       = "ExternalSecret"
      metadata = {
        name        = coalesce(try(cfg.name, null), key)
        namespace   = cfg.namespace
        labels      = merge(var.common_labels, lookup(cfg, "labels", {}))
        annotations = lookup(cfg, "annotations", {})
      }
      spec = merge(
        {
          refreshInterval = coalesce(lookup(cfg, "refresh_interval", null), var.default_refresh_interval)
          secretStoreRef = {
            name = coalesce(lookup(cfg, "secret_store_name", null), var.secret_store_name)
            kind = coalesce(lookup(cfg, "secret_store_kind", null), local.secret_store_kind)
          }
          target = merge(
            {
              name           = coalesce(try(cfg.target.name, null), coalesce(try(cfg.name, null), key))
              creationPolicy = coalesce(try(cfg.target.creation_policy, null), "Owner")
            },
            try(cfg.target.deletion_policy, null) != null ? { deletionPolicy = cfg.target.deletion_policy } : {},
            try(cfg.target.template, null) != null ? { template = cfg.target.template } : {},
          )
          data = [
            for item in lookup(cfg, "data", []) : merge(
              {
                secretKey = item.secret_key
                remoteRef = merge(
                  { key = item.remote_ref.key },
                  lookup(item.remote_ref, "property", null) != null ? { property = item.remote_ref.property } : {},
                  lookup(item.remote_ref, "version", null) != null ? { version = item.remote_ref.version } : {},
                )
              }
            )
          ]
        },
        length(lookup(cfg, "data_from", [])) > 0 ? {
          dataFrom = [for df in cfg.data_from : df]
        } : {},
      )
    }
  } : {}
}

resource "helm_release" "operator" {
  count = local.operator_enabled ? 1 : 0

  name       = var.release_name
  namespace  = var.namespace
  repository = var.chart_repository
  chart      = var.chart_name
  version    = var.chart_version

  create_namespace = var.create_namespace
  wait             = true
  timeout          = var.helm_timeout_seconds
  atomic           = true
  cleanup_on_fail  = true

  values = local.rendered_helm_values
}

resource "kubernetes_manifest" "secret_store" {
  count = local.operator_enabled && var.secret_store_scope == "namespace" ? 1 : 0

  manifest = local.secret_store_manifest

  depends_on = [helm_release.operator]
}

resource "kubernetes_manifest" "cluster_secret_store" {
  count = local.operator_enabled && var.secret_store_scope == "cluster" ? 1 : 0

  manifest = local.secret_store_manifest

  depends_on = [helm_release.operator]
}

resource "kubernetes_manifest" "external_secret" {
  for_each = local.operator_enabled ? local.managed_external_secrets : {}

  manifest = each.value

  depends_on = concat(
    [helm_release.operator],
    var.secret_store_scope == "namespace" ? [kubernetes_manifest.secret_store[0]] : [],
    var.secret_store_scope == "cluster" ? [kubernetes_manifest.cluster_secret_store[0]] : [],
  )
}
