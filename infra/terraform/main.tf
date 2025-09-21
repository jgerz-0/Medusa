terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }

    externalsecrets = {
      source  = "external-secrets/external-secrets"
      version = "~> 0.9"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    bucket         = "medusa-terraform-state"
    key            = "global/platform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "medusa-terraform-locks"
  }
}

# AWS is the control plane for almost everything in the platform. We rely on
# Terraform locals and variables to keep regions, project naming, and tagging
# consistent across environments.
provider "aws" {
  region  = local.aws_region
  profile = local.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

# Kubernetes resources are managed via kubeconfig by default. This keeps the
# provider lean and defers credential sourcing to the caller (normally a CI/CD
# job or a security engineer's workstation with short-lived credentials).
provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = coalesce(var.kubeconfig_context, local.environment_context.kube_context)
}

# Helm releases reuse the same Kubernetes authentication material to avoid
# duplicate credential stores.
provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = coalesce(var.kubeconfig_context, local.environment_context.kube_context)
  }

  registry_config_path = var.helm_registry_config
}

# External Secrets needs access to the target Kubernetes API just like Helm.
provider "externalsecrets" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = coalesce(var.kubeconfig_context, local.environment_context.kube_context)
  }
}

module "eks" {
  source = "./modules/eks"

  vpc_cidr = var.vpc_cidr
  availability_zones = var.availability_zones
  private_subnet_cidrs = var.private_subnet_cidrs
  public_subnet_cidrs = var.public_subnet_cidrs
  cluster_name = local.cluster_name
  cluster_version = var.cluster_version
  cluster_endpoint_public_access = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  cluster_log_types = var.cluster_log_types
  cloudwatch_log_retention_in_days = var.cloudwatch_log_retention_in_days
  cluster_iam_role_name = var.cluster_iam_role_name
  cluster_iam_role_additional_policy_arns = var.cluster_iam_role_additional_policy_arns
  node_iam_role_name = var.node_iam_role_name
  node_iam_role_additional_policy_arns = var.node_iam_role_additional_policy_arns
  default_node_group_disk_size = var.default_node_group_disk_size
  managed_node_groups = var.managed_node_groups
  tags = local.common_tags
}

data "aws_eks_cluster_auth" "medusa" {
  name = local.cluster_name

  depends_on = [module.eks]
}

resource "random_password" "medusa_callback" {
  for_each = {
    nuclei        = true
    enrichment    = true
    binary_static = true
    binary_fuzzing = true
    sqlmap        = true
    zap           = true
    validator     = true
  }

  length  = 40
  special = false
}

locals {
  medusa_callback_tokens = {
    nuclei         = random_password.medusa_callback["nuclei"].result
    enrichment     = random_password.medusa_callback["enrichment"].result
    binary_static  = random_password.medusa_callback["binary_static"].result
    binary_fuzzing = random_password.medusa_callback["binary_fuzzing"].result
    sqlmap         = random_password.medusa_callback["sqlmap"].result
    zap            = random_password.medusa_callback["zap"].result
    validator      = random_password.medusa_callback["validator"].result
  }

  medusa_bucket_names = merge(
    {
      artifact = module.s3.artifact_bucket.name
      analysis = module.s3.artifact_bucket.name
      fuzzing  = module.s3.artifact_bucket.name
      metadata = module.s3.artifact_bucket.name
    },
    var.medusa_bucket_overrides,
  )

  external_secrets_operator_enabled = var.enable_external_secrets_operator

  external_secrets_irsa_role_arn_effective = coalesce(
    var.external_secrets_irsa_role_arn,
    lookup(var.external_secrets_service_account_annotations, "eks.amazonaws.com/role-arn", null),
  )

  medusa_external_secret_template_data = merge(
    {
      BINARY_ANALYSIS_BUCKET                       = local.medusa_bucket_names.analysis
      BINARY_ANALYSIS_PREFIX                       = "analysis/reports/"
      BINARY_FUZZING_BUCKET                        = local.medusa_bucket_names.fuzzing
      BINARY_FUZZING_DEAD_LETTER_KEY               = "queues:binary:fuzzing:dead"
      BINARY_FUZZING_PREFIX                        = "analysis/fuzzing/"
      BINARY_METADATA_BUCKET                       = local.medusa_bucket_names.metadata
      BINARY_METADATA_PREFIX                       = "preprocess/metadata/"
      BINARY_PREPROCESS_DEAD_LETTER_KEY            = "queues:binary:preprocess:dead"
      BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY       = "queues:binary:static-analysis:dead"
      CVE_ENRICHMENT_ERROR_QUEUE_KEY               = "queues:enrichment:cve:errors"
      CVE_ENRICHMENT_QDRANT_API_KEY                = ""
      CVE_ENRICHMENT_QDRANT_COLLECTION             = "medusa-advisories"
      CVE_ENRICHMENT_QDRANT_URL                    = ""
      CVE_ENRICHMENT_QUEUE_KEY                     = "queues:enrichment:cve"
      CVE_ENRICHMENT_RESULT_QUEUE_KEY              = "queues:enrichment:cve:results"
      MEDUSA_ANALYST_API_KEY                       = ""
      MEDUSA_BINARY_FUZZING_CALLBACK_TOKEN         = local.medusa_callback_tokens.binary_fuzzing
      MEDUSA_BINARY_FUZZING_QUEUE_CHANNEL          = "queues:binary:fuzzing"
      MEDUSA_BINARY_PREPROCESS_QUEUE_CHANNEL       = "queues:binary:preprocess"
      MEDUSA_BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN = local.medusa_callback_tokens.binary_static
      MEDUSA_BINARY_STATIC_ANALYSIS_QUEUE_CHANNEL  = "queues:binary:static-analysis"
      MEDUSA_CVE_ENRICHMENT_QUEUE_CHANNEL          = "queues:enrichment:cve"
      MEDUSA_DATABASE_URL                          = format(
        "postgresql://{{ .medusaDatabaseUsername }}:{{ .medusaDatabasePassword }}@%s:%d/%s",
        module.rds.controller_context.hostname,
        module.rds.controller_context.port,
        module.rds.controller_context.database,
      )
      MEDUSA_ENRICHMENT_CALLBACK_TOKEN             = local.medusa_callback_tokens.enrichment
      MEDUSA_JWT_SECRET                            = "change-me"
      MEDUSA_NUCLEI_CALLBACK_TOKEN                 = local.medusa_callback_tokens.nuclei
      MEDUSA_NUCLEI_QUEUE_CHANNEL                  = "queues:nuclei:jobs"
      MEDUSA_POSTGRES_PASSWORD                     = "{{ .medusaDatabasePassword }}"
      MEDUSA_REDIS_URL                             = "redis://redis-master:6379/0"
      MEDUSA_SQLMAP_CALLBACK_TOKEN                 = local.medusa_callback_tokens.sqlmap
      MEDUSA_SQLMAP_DEAD_LETTER_KEY                = "queues:sqlmap:dead"
      MEDUSA_SQLMAP_QUEUE_CHANNEL                  = "queues:sqlmap:jobs"
      MEDUSA_VALIDATOR_CALLBACK_TOKEN              = local.medusa_callback_tokens.validator
      MEDUSA_VALIDATOR_DEAD_LETTER_KEY             = "queues:validator:dead"
      MEDUSA_VALIDATOR_QUEUE_CHANNEL               = "queues:validator:jobs"
      MEDUSA_ZAP_CALLBACK_TOKEN                    = local.medusa_callback_tokens.zap
      MEDUSA_ZAP_DEAD_LETTER_KEY                   = "queues:zap:dead"
      MEDUSA_ZAP_QUEUE_CHANNEL                     = "queues:zap:jobs"
      NUCLEI_ARTIFACT_BUCKET                       = local.medusa_bucket_names.artifact
      NUCLEI_CALLBACK_TOKEN                        = local.medusa_callback_tokens.nuclei
      SQLMAP_CALLBACK_TOKEN                        = local.medusa_callback_tokens.sqlmap
      VALIDATOR_CALLBACK_TOKEN                     = local.medusa_callback_tokens.validator
      ZAP_CALLBACK_TOKEN                           = local.medusa_callback_tokens.zap
    },
    var.medusa_inline_secret_overrides,
  )

  medusa_external_secret_configuration_effective = local.external_secrets_operator_enabled ? {
    secret_store_kind = module.external_secrets.secret_store_kind
    secret_store_name = module.external_secrets.secret_store_name
    refresh_interval  = var.external_secrets_medusa_refresh_interval
    data              = module.external_secrets.medusa_database_remote_refs
    target_template = {
      type = "Opaque"
      data = local.medusa_external_secret_template_data
    }
  } : var.medusa_external_secret_configuration

  medusa_secret_strategy_effective = local.external_secrets_operator_enabled ? "externalSecret" : var.medusa_secret_strategy

  medusa_manage_inline_secret_effective = (
    local.medusa_secret_strategy_effective == "inline"
    && !local.external_secrets_operator_enabled
  ) ? var.medusa_manage_inline_secret : false

  medusa_manage_external_secret_effective = local.medusa_secret_strategy_effective == "externalSecret" ? (
    local.external_secrets_operator_enabled ? true : var.medusa_manage_external_secret
  ) : false

  medusa_manage_sealed_secret_effective = (
    local.medusa_secret_strategy_effective == "sealedSecret"
    && !local.external_secrets_operator_enabled
  ) ? var.medusa_manage_sealed_secret : false

  medusa_sealed_secret_configuration_effective = local.medusa_secret_strategy_effective == "sealedSecret" ? var.medusa_sealed_secret_configuration : null

  alb_controller_enabled = var.enable_aws_lb_controller

  medusa_controller_ingress_class_name_effective = coalesce(
    var.medusa_controller_ingress_class_name,
    local.alb_controller_enabled ? module.aws_lb_controller.ingress_class_name : null,
  )

  medusa_controller_ingress_annotations = merge(
    local.alb_controller_enabled ? module.aws_lb_controller.ingress_annotations : {},
    var.medusa_controller_ingress_additional_annotations,
  )

  medusa_controller_ingress_hosts_rendered = [
    for host in var.medusa_controller_ingress_hosts : {
      host  = host.host
      paths = [
        for path in host.paths : {
          path     = path.path
          pathType = coalesce(path.path_type, "Prefix")
        }
      ]
    }
  ]

  medusa_controller_ingress_tls_rendered = [
    for tls in var.medusa_controller_ingress_tls : {
      hosts      = tls.hosts
      secretName = tls.secret_name
    }
  ]

  medusa_controller_ingress_values = (
    var.medusa_controller_ingress_enabled
    ? [
        {
          controller = {
            ingress = merge(
              { enabled = true },
              local.medusa_controller_ingress_class_name_effective != null ? {
                className = local.medusa_controller_ingress_class_name_effective
              } : {},
              local.medusa_controller_ingress_annotations != {} ? {
                annotations = local.medusa_controller_ingress_annotations
              } : {},
              length(local.medusa_controller_ingress_hosts_rendered) > 0 ? {
                hosts = local.medusa_controller_ingress_hosts_rendered
              } : {},
              length(local.medusa_controller_ingress_tls_rendered) > 0 ? {
                tls = local.medusa_controller_ingress_tls_rendered
              } : {},
              var.medusa_controller_ingress_extra_settings,
            )
          }
        }
      ]
    : []
  )
}

module "observability" {
  source = "./modules/observability"

  enabled              = var.enable_observability
  mode                 = var.observability_mode
  namespace            = var.observability_namespace
  create_namespace     = var.observability_create_namespace
  release_name         = var.observability_release_name
  chart_repository     = var.observability_chart_repository
  chart_name           = var.observability_chart_name
  chart_version        = var.observability_chart_version
  helm_timeout_seconds = var.observability_helm_timeout_seconds

  medusa_namespace    = local.environment_context.namespace
  medusa_release_name = local.environment_context.helm_release

  service_monitor_labels         = var.observability_service_monitor_labels
  service_monitor_interval       = var.observability_service_monitor_interval
  service_monitor_scrape_timeout = var.observability_service_monitor_scrape_timeout
  embedded_service_monitor_enabled = var.observability_embedded_service_monitor_enabled
  prometheus_retention           = var.observability_prometheus_retention
  embedded_prometheus_persistent_volume_enabled = var.observability_embedded_prometheus_persistent_volume_enabled
  embedded_prometheus_storage_class             = var.observability_embedded_prometheus_storage_class
  embedded_prometheus_storage_size              = var.observability_embedded_prometheus_storage_size
  embedded_prometheus_service_type              = var.observability_embedded_prometheus_service_type

  grafana_service_type                = var.observability_grafana_service_type
  grafana_ingress_enabled             = var.observability_grafana_ingress_enabled
  grafana_ingress_class_name          = var.observability_grafana_ingress_class_name
  grafana_ingress_annotations         = var.observability_grafana_ingress_annotations
  grafana_ingress_hosts               = var.observability_grafana_ingress_hosts
  grafana_ingress_tls                 = var.observability_grafana_ingress_tls
  grafana_ingress_additional_settings = var.observability_grafana_ingress_additional_settings

  manage_grafana_admin_secret      = var.observability_manage_grafana_admin_secret
  grafana_admin_secret_name        = var.observability_grafana_admin_secret_name
  grafana_admin_user_key           = var.observability_grafana_admin_user_key
  grafana_admin_password_key       = var.observability_grafana_admin_password_key
  grafana_admin_secret_labels      = var.observability_grafana_admin_secret_labels
  grafana_admin_secret_annotations = var.observability_grafana_admin_secret_annotations
  grafana_admin_credentials        = var.observability_grafana_admin_credentials

  enable_alertmanager            = var.observability_enable_alertmanager
  alertmanager_config            = var.observability_alertmanager_config
  alertmanager_additional_values = var.observability_alertmanager_additional_values
  kube_prometheus_additional_values = var.observability_kube_prometheus_additional_values
  embedded_additional_values        = var.observability_embedded_additional_values
  external_stack_medusa_overrides   = var.observability_external_stack_medusa_overrides

  common_labels = merge(
    {
      "app.kubernetes.io/managed-by" = "terraform"
      "medusa.security/environment"  = local.environment
      "medusa.security/project"      = local.project_name
    },
    var.observability_additional_labels,
  )
}

module "medusa" {
  source = "./modules/medusa"

  cluster_name                       = local.cluster_name
  cluster_endpoint                   = module.eks.cluster_endpoint
  cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
  cluster_token                      = data.aws_eks_cluster_auth.medusa.token

  namespace    = local.environment_context.namespace
  release_name = local.environment_context.helm_release

  secret_name     = var.medusa_secret_name
  secret_strategy = local.medusa_secret_strategy_effective

  manage_inline_secret   = local.medusa_manage_inline_secret_effective
  manage_external_secret = local.medusa_manage_external_secret_effective
  manage_sealed_secret   = local.medusa_manage_sealed_secret_effective

  database = {
    hostname          = module.rds.controller_context.hostname
    port              = module.rds.controller_context.port
    database          = module.rds.controller_context.database
    connection_string = module.rds.controller_context.connection_string
    secret_arn        = module.rds.controller_context.secret_arn
    secret_name       = module.rds.controller_context.secret_name
  }

  bucket_names    = local.medusa_bucket_names

  callback_tokens = local.medusa_callback_tokens

  inline_secret_overrides       = var.medusa_inline_secret_overrides
  external_secret_configuration = local.medusa_external_secret_configuration_effective
  sealed_secret_configuration   = local.medusa_sealed_secret_configuration_effective
  controller_additional_env     = var.medusa_controller_additional_env
  extra_values = concat(
    var.medusa_extra_values,
    module.observability.medusa_extra_values,
    module.irsa.helm_values,
    local.medusa_controller_ingress_values,
  )
  common_labels = merge(
    {
      "app.kubernetes.io/managed-by" = "terraform"
      "medusa.security/environment"  = local.environment
      "medusa.security/project"      = local.project_name
    },
    var.medusa_additional_labels,
  )
  render_operator_kubeconfig = var.medusa_render_operator_kubeconfig
  helm_timeout_seconds       = var.medusa_helm_timeout_seconds

  depends_on = concat(
    [module.eks, module.rds, module.s3],
    var.enable_observability && var.observability_mode == "kube-prometheus-stack" ? [module.observability] : [],
  )
}

module "s3" {
  source = "./modules/s3"

  project_name = local.project_name
  environment  = local.environment

  artifact_bucket_name   = var.artifact_bucket_name
  artifact_bucket_prefix = var.artifact_bucket_prefix
  artifact_bucket_suffix = var.artifact_bucket_suffix
  force_destroy          = var.artifact_bucket_force_destroy
  versioning_enabled     = var.artifact_bucket_versioning_enabled

  enable_artifact_expiration           = var.artifact_enable_expiration
  artifact_retention_days              = var.artifact_retention_days
  enable_noncurrent_version_expiration = var.artifact_enable_noncurrent_version_expiration
  noncurrent_version_retention_days    = var.artifact_noncurrent_version_retention_days
  abort_incomplete_multipart_upload_days = var.artifact_abort_incomplete_multipart_upload_days

  worker_access = var.artifact_worker_prefixes

  create_kms_key                   = var.artifact_create_kms_key
  kms_key_arn                      = var.artifact_kms_key_arn
  kms_key_alias                    = var.artifact_kms_key_alias
  kms_key_deletion_window_in_days  = var.artifact_kms_deletion_window_in_days

  tags = local.common_tags
}

module "irsa" {
  source = "./modules/irsa"

  enabled     = var.enable_medusa_irsa
  namespace   = local.environment_context.namespace
  release_name = local.environment_context.helm_release

  cluster_oidc_issuer_url      = module.eks.cluster_oidc_issuer_url
  controller_policy_document   = module.s3.controller_policy_document
  worker_policy_documents      = module.s3.worker_policy_documents
  controller_service_account   = var.medusa_irsa_controller_service_account
  worker_service_accounts      = local.medusa_irsa_worker_service_accounts

  tags = local.common_tags
}

module "aws_lb_controller" {
  source = "./modules/aws_lb_controller"

  enabled                 = var.enable_aws_lb_controller
  cluster_name            = local.cluster_name
  cluster_region          = local.aws_region
  cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
  vpc_id                  = module.eks.vpc_id
  private_subnet_ids      = module.eks.private_subnet_ids
  public_subnet_ids       = module.eks.public_subnet_ids

  namespace        = var.aws_lb_controller_namespace
  release_name     = var.aws_lb_controller_release_name
  chart_repository = var.aws_lb_controller_chart_repository
  chart_name       = var.aws_lb_controller_chart_name
  chart_version    = var.aws_lb_controller_chart_version
  create_namespace = var.aws_lb_controller_create_namespace
  service_account  = var.aws_lb_controller_service_account
  iam_role_name    = var.aws_lb_controller_iam_role_name

  additional_policy_arns   = var.aws_lb_controller_additional_policy_arns
  helm_additional_values   = var.aws_lb_controller_additional_helm_values
  helm_timeout_seconds     = var.aws_lb_controller_helm_timeout_seconds
  load_balancer_scheme     = var.aws_lb_controller_scheme
  load_balancer_ip_address_type = var.aws_lb_controller_ip_address_type
  target_type                    = var.aws_lb_controller_target_type
  ingress_class_name             = var.aws_lb_controller_ingress_class_name
  ingress_class_params_name      = var.aws_lb_controller_ingress_class_params_name
  set_default_ingress_class      = var.aws_lb_controller_set_default_ingress_class
  load_balancer_certificate_arn  = var.aws_lb_controller_certificate_arn
  load_balancer_ssl_policy       = var.aws_lb_controller_ssl_policy
  load_balancer_additional_annotations = var.aws_lb_controller_additional_annotations
  load_balancer_additional_tags        = var.aws_lb_controller_additional_tags
  load_balancer_security_group_ids     = var.aws_lb_controller_security_group_ids
  node_selector                         = var.aws_lb_controller_node_selector
  tolerations                           = var.aws_lb_controller_tolerations

  tags = local.common_tags
}

module "external_secrets" {
  source = "./modules/external-secrets"

  enabled               = var.enable_external_secrets_operator
  namespace             = var.external_secrets_namespace
  release_name          = var.external_secrets_release_name
  chart_version         = var.external_secrets_chart_version
  create_namespace      = var.external_secrets_create_namespace
  install_crds          = var.external_secrets_install_crds
  service_account_name  = var.external_secrets_service_account_name
  service_account_annotations = var.external_secrets_service_account_annotations
  irsa_role_arn         = local.external_secrets_irsa_role_arn_effective

  cluster_name = local.cluster_name
  aws_region   = local.aws_region

  secret_store_name        = var.external_secrets_secret_store_name
  secret_store_scope       = var.external_secrets_secret_store_scope
  secret_store_annotations = var.external_secrets_secret_store_annotations

  rds_master_secret_arn    = module.rds.master_credentials_secret_arn
  default_refresh_interval = var.external_secrets_default_refresh_interval
  external_secrets         = var.external_secrets_external_secrets

  additional_helm_values = var.external_secrets_additional_helm_values
  helm_timeout_seconds   = var.external_secrets_helm_timeout_seconds
  common_labels          = local.external_secrets_common_labels
}

module "rds" {
  source = "./modules/rds"

  database_name        = var.rds_database_name
  instance_class       = var.rds_instance_class
  engine               = var.rds_engine
  engine_version       = var.rds_engine_version
  port                 = var.rds_port
  allocated_storage    = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  instance_identifier  = var.rds_instance_identifier
  vpc_id               = module.eks.vpc_id
  subnet_ids           = module.eks.private_subnet_ids
  allowed_security_group_ids = [module.eks.node_security_group_id]
  master_username      = var.rds_master_username
  kms_key_arn          = var.rds_kms_key_arn
  master_secret_kms_key_arn = var.rds_master_secret_kms_key_arn
  backup_retention_period = var.rds_backup_retention_period
  preferred_backup_window = var.rds_preferred_backup_window
  preferred_maintenance_window = var.rds_preferred_maintenance_window
  multi_az             = var.rds_multi_az
  deletion_protection  = var.rds_deletion_protection
  skip_final_snapshot  = var.rds_skip_final_snapshot
  apply_immediately    = var.rds_apply_immediately
  monitoring_interval  = var.rds_monitoring_interval
  iam_database_authentication_enabled = var.rds_iam_authentication_enabled
  performance_insights_enabled        = var.rds_performance_insights_enabled
  performance_insights_kms_key_arn    = var.rds_performance_insights_kms_key_arn
  master_secret_name                  = var.rds_master_secret_name
  master_secret_description           = var.rds_master_secret_description
  master_secret_rotation_enabled      = var.rds_master_secret_rotation_enabled
  master_secret_rotation_lambda_arn   = var.rds_master_secret_rotation_lambda_arn
  master_secret_rotation_automatically_after_days = var.rds_master_secret_rotation_automatically_after_days
  tags = local.common_tags
}

locals {
  medusa_irsa_worker_defaults = {
    nuclei = {
      helm_worker_key = "nuclei"
    }
    binary_preprocess = {
      helm_worker_key = "binaryPreprocess"
    }
    binary_fuzzing = {
      helm_worker_key = "binaryFuzzing"
    }
    binary_static_analysis = {
      helm_worker_key = "binaryStaticAnalysis"
    }
    validator = {
      helm_worker_key = "validator"
    }
  }

  medusa_irsa_worker_service_accounts = {
    for worker in setunion(
      toset(keys(local.medusa_irsa_worker_defaults)),
      toset(keys(var.medusa_irsa_worker_service_accounts)),
    ) :
    worker => merge(
      lookup(local.medusa_irsa_worker_defaults, worker, {}),
      lookup(var.medusa_irsa_worker_service_accounts, worker, {}),
    )
  }

  external_secrets_common_labels = merge(
    {
      "app.kubernetes.io/managed-by" = "terraform"
      "medusa.security/environment"  = local.environment
      "medusa.security/project"      = local.project_name
    },
    var.external_secrets_additional_labels,
  )

  eks_context = {
    cluster_endpoint = module.eks.cluster_endpoint
    cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
    cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
    node_security_group_id = module.eks.node_security_group_id
    cluster_iam_role_arn = module.eks.cluster_iam_role_arn
    node_iam_role_arns = module.eks.node_iam_role_arns
  }

  artifact_storage_context = module.s3.context

  rds_context = module.rds.controller_context

  rds_network = {
    security_group_id  = module.rds.security_group_id
    subnet_group_name  = module.rds.subnet_group_name
    database_identifier = module.rds.database_identifier
  }
}
