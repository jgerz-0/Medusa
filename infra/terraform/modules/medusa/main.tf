terraform {
  required_version = ">= 1.5.7"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

provider "kubernetes" {
  host                   = var.cluster_endpoint
  cluster_ca_certificate = base64decode(var.cluster_certificate_authority_data)
  token                  = var.cluster_token
}

provider "helm" {
  kubernetes {
    host                   = var.cluster_endpoint
    cluster_ca_certificate = base64decode(var.cluster_certificate_authority_data)
    token                  = var.cluster_token
  }
}

locals {
  chart_path = abspath("${path.root}/../helm/medusa")

  bucket_names = merge(
    {
      artifact = lookup(var.bucket_names, "artifact", "")
      analysis = lookup(var.bucket_names, "analysis", lookup(var.bucket_names, "artifact", ""))
      fuzzing  = lookup(var.bucket_names, "fuzzing", lookup(var.bucket_names, "artifact", ""))
      metadata = lookup(var.bucket_names, "metadata", lookup(var.bucket_names, "artifact", ""))
    },
    var.bucket_names,
  )

  callback_tokens = merge(
    {
      nuclei        = null,
      sqlmap        = null,
      enrichment    = null,
      binary_static = null,
      binary_fuzzing = null,
      binary_symbolic = null,
      zap           = null,
      validator     = null,
    },
    var.callback_tokens,
  )

  inline_secret_values = merge(
    {
      BINARY_ANALYSIS_BUCKET                       = local.bucket_names.analysis
      BINARY_ANALYSIS_PREFIX                       = "analysis/reports/"
      BINARY_FUZZING_BUCKET                        = local.bucket_names.fuzzing
      BINARY_FUZZING_DEAD_LETTER_KEY               = "queues:binary:fuzzing:dead"
      BINARY_FUZZING_PREFIX                        = "analysis/fuzzing/"
      BINARY_METADATA_BUCKET                       = local.bucket_names.metadata
      BINARY_METADATA_PREFIX                       = "preprocess/metadata/"
      BINARY_PREPROCESS_DEAD_LETTER_KEY            = "queues:binary:preprocess:dead"
      BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY       = "queues:binary:static-analysis:dead"
      BINARY_SYMBOLIC_EXECUTION_DEAD_LETTER_KEY    = "queues:binary:symbolic-execution:dead"
      BINARY_SYMBOLIC_EXECUTION_BUCKET             = local.bucket_names.analysis
      BINARY_SYMBOLIC_EXECUTION_PREFIX             = "analysis/symbolic/"
      CVE_ENRICHMENT_ERROR_QUEUE_KEY               = "queues:enrichment:cve:errors"
      CVE_ENRICHMENT_QDRANT_API_KEY                = ""
      CVE_ENRICHMENT_QDRANT_COLLECTION             = "medusa-advisories"
      CVE_ENRICHMENT_QDRANT_URL                    = ""
      CVE_ENRICHMENT_QUEUE_KEY                     = "queues:enrichment:cve"
      CVE_ENRICHMENT_RESULT_QUEUE_KEY              = "queues:enrichment:cve:results"
      MEDUSA_ANALYST_API_KEY                       = ""
      MEDUSA_BINARY_FUZZING_CALLBACK_TOKEN         = local.callback_tokens.binary_fuzzing
      MEDUSA_BINARY_FUZZING_QUEUE_CHANNEL          = "queues:binary:fuzzing"
      MEDUSA_BINARY_PREPROCESS_QUEUE_CHANNEL       = "queues:binary:preprocess"
      MEDUSA_BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN = local.callback_tokens.binary_static
      MEDUSA_BINARY_STATIC_ANALYSIS_QUEUE_CHANNEL  = "queues:binary:static-analysis"
      MEDUSA_BINARY_SYMBOLIC_EXECUTION_CALLBACK_TOKEN = local.callback_tokens.binary_symbolic
      MEDUSA_BINARY_SYMBOLIC_EXECUTION_QUEUE_CHANNEL  = "queues:binary:symbolic-execution"
      MEDUSA_CVE_ENRICHMENT_QUEUE_CHANNEL          = "queues:enrichment:cve"
      MEDUSA_DATABASE_URL                          = var.database.connection_string
      MEDUSA_ENRICHMENT_CALLBACK_TOKEN             = local.callback_tokens.enrichment
      MEDUSA_JWT_SECRET                            = "change-me"
      MEDUSA_NUCLEI_CALLBACK_TOKEN                 = local.callback_tokens.nuclei
      MEDUSA_NUCLEI_QUEUE_CHANNEL                  = "queues:nuclei:jobs"
      MEDUSA_POSTGRES_PASSWORD                     = "change-me"
      MEDUSA_REDIS_URL                             = "redis://redis-master:6379/0"
      MEDUSA_SQLMAP_CALLBACK_TOKEN                 = local.callback_tokens.sqlmap
      MEDUSA_SQLMAP_DEAD_LETTER_KEY                = "queues:sqlmap:dead"
      MEDUSA_SQLMAP_QUEUE_CHANNEL                  = "queues:sqlmap:jobs"
      MEDUSA_VALIDATOR_CALLBACK_TOKEN              = local.callback_tokens.validator
      MEDUSA_VALIDATOR_DEAD_LETTER_KEY             = "queues:validator:dead"
      MEDUSA_VALIDATOR_QUEUE_CHANNEL               = "queues:validator:jobs"
      MEDUSA_ZAP_CALLBACK_TOKEN                    = local.callback_tokens.zap
      MEDUSA_ZAP_DEAD_LETTER_KEY                   = "queues:zap:dead"
      MEDUSA_ZAP_QUEUE_CHANNEL                     = "queues:zap:jobs"
      MINIO_ROOT_PASSWORD                          = "medusaadmin123"
      MINIO_ROOT_USER                              = "medusaadmin"
      MINIO_SITE_REGION                            = "us-east-1"
      NUCLEI_ARTIFACT_BUCKET                       = local.bucket_names.artifact
      NUCLEI_CALLBACK_TOKEN                        = local.callback_tokens.nuclei
      S3_ACCESS_KEY                                = "medusaadmin"
      S3_ACCESS_KEY_ID                             = "medusaadmin"
      S3_SECRET_ACCESS_KEY                         = "medusaadmin123"
      S3_SECRET_KEY                                = "medusaadmin123"
      SQLMAP_CALLBACK_TOKEN                        = local.callback_tokens.sqlmap
      VALIDATOR_CALLBACK_TOKEN                     = local.callback_tokens.validator
      ZAP_CALLBACK_TOKEN                           = local.callback_tokens.zap
    },
    var.inline_secret_overrides,
  )

  render_inline_secret = var.secret_strategy == "inline" && !var.manage_inline_secret

  render_sealed_secret = var.secret_strategy == "sealedSecret" && !var.manage_sealed_secret

  sealed_secret_annotations = merge(
    {
      "medusa.security/description" = "SealedSecret envelope for Medusa credentials."
    },
    var.sealed_secret_configuration != null ? try(var.sealed_secret_configuration.template_annotations, {}) : {},
  )

  sealed_secret_values = var.sealed_secret_configuration != null ? {
    encryptedData = local.render_sealed_secret ? var.sealed_secret_configuration.encrypted_data : {}
    annotations   = local.sealed_secret_annotations
  } : null

  external_secret_configuration = (
    var.secret_strategy == "externalSecret" && var.external_secret_configuration != null
  ) ? {
    secretStoreKind = var.external_secret_configuration.secret_store_kind
    secretStoreName = var.external_secret_configuration.secret_store_name
    refreshInterval = coalesce(var.external_secret_configuration.refresh_interval, "1h")
    data            = var.manage_external_secret ? [] : coalesce(var.external_secret_configuration.data, [])
  } : null

  external_secret_manifest_spec = (
    var.secret_strategy == "externalSecret" && var.external_secret_configuration != null
  ) ? merge(
    {
      refreshInterval = coalesce(var.external_secret_configuration.refresh_interval, "1h")
      secretStoreRef = {
        kind = var.external_secret_configuration.secret_store_kind
        name = var.external_secret_configuration.secret_store_name
      }
      target = merge(
        {
          name           = var.secret_name
          creationPolicy = "Owner"
        },
        var.external_secret_configuration.target_template != null ? {
          template = var.external_secret_configuration.target_template
        } : {},
      )
      data = coalesce(var.external_secret_configuration.data, [])
    },
    (
      var.external_secret_configuration.data_from != null
      && length(var.external_secret_configuration.data_from) > 0
    ) ? {
      dataFrom = var.external_secret_configuration.data_from
    } : {},
  ) : null

  sealed_secret_metadata_labels = merge(
    var.common_labels,
    {
      "app.kubernetes.io/name"       = "medusa"
      "app.kubernetes.io/instance"   = var.release_name
      "app.kubernetes.io/managed-by" = "terraform"
      "app.kubernetes.io/component"  = "secrets"
    },
    var.sealed_secret_configuration != null ? try(var.sealed_secret_configuration.metadata_labels, {}) : {},
  )

  sealed_secret_metadata_annotations = merge(
    {
      "medusa.security/description" = "SealedSecret envelope for Medusa credentials."
    },
    var.sealed_secret_configuration != null ? try(var.sealed_secret_configuration.metadata_annotations, {}) : {},
  )

  sealed_secret_template_labels = merge(
    var.common_labels,
    {
      "app.kubernetes.io/name"      = "medusa"
      "app.kubernetes.io/instance"  = var.release_name
      "app.kubernetes.io/component" = "secrets"
    },
    var.sealed_secret_configuration != null ? try(var.sealed_secret_configuration.template_labels, {}) : {},
  )

  sealed_secret_template_annotations = local.sealed_secret_annotations

  sealed_secret_template_type = var.sealed_secret_configuration != null ? coalesce(
    try(var.sealed_secret_configuration.template_type, null),
    "Opaque",
  ) : "Opaque"

  sealed_secret_manifest = var.secret_strategy == "sealedSecret" && var.sealed_secret_configuration != null ? {
    apiVersion = "bitnami.com/v1alpha1"
    kind       = "SealedSecret"
    metadata = {
      name        = var.secret_name
      namespace   = var.namespace
      labels      = local.sealed_secret_metadata_labels
      annotations = local.sealed_secret_metadata_annotations
    }
    spec = {
      encryptedData = var.sealed_secret_configuration.encrypted_data
      template = {
        metadata = {
          name        = var.secret_name
          labels      = local.sealed_secret_template_labels
          annotations = local.sealed_secret_template_annotations
        }
        type = local.sealed_secret_template_type
      }
    }
  } : null

  controller_ingress_waf_acl = trimspace(coalesce(
    try(var.controller_ingress_security.waf.web_acl_arn, null),
    "",
  ))

  controller_ingress_security = {
    shield_enabled = coalesce(
      try(var.controller_ingress_security.shield_enabled, null),
      false,
    )
    waf = {
      enabled = coalesce(
        try(var.controller_ingress_security.waf.enabled, null),
        false,
      )
      web_acl_arn = local.controller_ingress_waf_acl != "" ? local.controller_ingress_waf_acl : null
      fail_open = coalesce(
        try(var.controller_ingress_security.waf.fail_open, null),
        false,
      )
    }
  }

  base_helm_values = {
    secrets = {
      strategy       = var.secret_strategy
      name           = var.secret_name
      inline         = local.render_inline_secret ? local.inline_secret_values : null
      externalSecret = local.external_secret_configuration
      sealedSecret   = local.sealed_secret_values
    }
    controller = {
      env = {
        extra = concat(
          [
            {
              name  = "MEDUSA_DATABASE_HOST"
              value = var.database.hostname
            },
            {
              name  = "MEDUSA_DATABASE_PORT"
              value = tostring(var.database.port)
            },
            {
              name  = "MEDUSA_DATABASE_NAME"
              value = var.database.database
            },
            {
              name  = "MEDUSA_DATABASE_SECRET_ARN"
              value = var.database.secret_arn
            },
            {
              name  = "MEDUSA_ARTIFACT_BUCKET"
              value = local.bucket_names.artifact
            },
            {
              name  = "MEDUSA_METADATA_BUCKET"
              value = local.bucket_names.metadata
            },
          ],
          var.controller_additional_env,
        )
      }
      ingress = {
        aws = {
          shield = {
            enabled = local.controller_ingress_security.shield_enabled
          }
          waf = merge(
            {
              enabled = local.controller_ingress_security.waf.enabled
              failOpen = local.controller_ingress_security.waf.fail_open
            },
            local.controller_ingress_security.waf.web_acl_arn != null ? {
              webAclArn = local.controller_ingress_security.waf.web_acl_arn
            } : {},
          )
        }
      }
    }
    minio = {
      existingSecret = var.secret_name
    }
    podSecurityStandards = {
      namespaceLabelsOnly = true
    }
  }

  rendered_helm_values = concat(
    [yamlencode(local.base_helm_values)],
    [for value in var.extra_values : yamlencode(value)],
  )

  operator_kubeconfig = var.render_operator_kubeconfig ? yamlencode({
    apiVersion = "v1"
    kind       = "Config"
    clusters = [
      {
        cluster = {
          server                     = var.cluster_endpoint
          certificate-authority-data = var.cluster_certificate_authority_data
        }
        name = var.cluster_name
      }
    ]
    contexts = [
      {
        context = {
          cluster = var.cluster_name
          user    = "${var.cluster_name}-terraform"
        }
        name = var.cluster_name
      }
    ]
    "current-context" = var.cluster_name
    preferences        = {}
    users = [
      {
        name = "${var.cluster_name}-terraform"
        user = {
          token = var.cluster_token
        }
      }
    ]
  }) : null
}

resource "kubernetes_namespace" "medusa" {
  metadata {
    name = var.namespace
    labels = merge(
      var.common_labels,
      {
        "medusa.security/scope" = "application"
      },
      { for key, value in var.namespace_pod_security_standards : "pod-security.kubernetes.io/${key}" => value },
    )
  }
}

resource "kubernetes_secret" "inline" {
  count = var.secret_strategy == "inline" && var.manage_inline_secret ? 1 : 0

  metadata {
    name      = var.secret_name
    namespace = var.namespace
    labels = merge(
      var.common_labels,
      {
        "app.kubernetes.io/name"       = var.release_name
        "app.kubernetes.io/component"  = "secrets"
        "medusa.security/description"  = "Inline Medusa secret managed by Terraform"
      },
    )
  }

  data = { for key, value in local.inline_secret_values : key => base64encode(value) }
  type = "Opaque"

  depends_on = [kubernetes_namespace.medusa]
}

resource "kubernetes_manifest" "external_secret" {
  count = var.secret_strategy == "externalSecret" && var.manage_external_secret ? 1 : 0

  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata = {
      name      = var.secret_name
      namespace = var.namespace
      labels = merge(
        var.common_labels,
        {
          "app.kubernetes.io/name"      = var.release_name
          "app.kubernetes.io/component" = "secrets"
        },
      )
      annotations = {
        "medusa.security/description" = "ExternalSecret binding Medusa credentials from central store"
      }
    }
    spec = merge(local.external_secret_manifest_spec, {
      target = merge(local.external_secret_manifest_spec.target, {
        name = var.secret_name
      })
    })
  }

  depends_on = [kubernetes_namespace.medusa]
}

resource "kubernetes_manifest" "sealed_secret" {
  count = var.secret_strategy == "sealedSecret" && var.manage_sealed_secret ? 1 : 0

  manifest = local.sealed_secret_manifest

  depends_on = [kubernetes_namespace.medusa]
}

resource "helm_release" "medusa" {
  name             = var.release_name
  namespace        = var.namespace
  chart            = local.chart_path
  dependency_update = true
  create_namespace = false
  wait             = true
  timeout          = var.helm_timeout_seconds
  atomic           = true
  cleanup_on_fail  = true

  values = local.rendered_helm_values

  depends_on = concat(
    [kubernetes_namespace.medusa],
    var.secret_strategy == "inline" && var.manage_inline_secret ? kubernetes_secret.inline : [],
    var.secret_strategy == "externalSecret" && var.manage_external_secret ? kubernetes_manifest.external_secret : [],
    var.secret_strategy == "sealedSecret" && var.manage_sealed_secret ? kubernetes_manifest.sealed_secret : [],
  )
}
