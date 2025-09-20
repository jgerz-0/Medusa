# Production environment defaults for the Medusa platform.
project_name                 = "medusa"
environment                  = "prod"
aws_profile                  = "medusa-prod"
aws_region                   = "us-east-1"
cluster_name                 = "medusa-prod"
state_bucket                 = "medusa-prod-terraform-state"
state_dynamodb_table         = "medusa-terraform-locks"
state_key_prefix             = "prod"
kubeconfig_path              = "~/.kube/config"
kubeconfig_context           = "medusa-prod"
helm_registry_config         = "~/.docker/config.json"
container_registry_server    = "ghcr.io"
container_registry_username  = "medusa-prod-bot"
container_registry_password  = "REPLACE_WITH_OIDC_TOKEN"
helm_repository_url          = "oci://ghcr.io/medusa/charts"
helm_repository_username     = "medusa-prod-bot"
helm_repository_password     = "REPLACE_WITH_OIDC_TOKEN"

# External Secrets Operator (disabled by default until production IRSA is in place).
enable_external_secrets_operator = false
external_secrets_secret_store_name = "medusa-prod-cluster-secrets"

# Observability stack (enable once ingress, RBAC, and alert routing are signed off).
enable_observability = false
observability_mode   = "kube-prometheus-stack"
# observability_manage_grafana_admin_secret = true
# observability_grafana_admin_credentials = {
#   username = "medusa-sre"
#   password = "REPLACE_WITH_SEALED_SECRET"
# }
# observability_grafana_ingress_enabled = true
# observability_grafana_ingress_hosts = [
#   {
#     host = "grafana.prod.example.com"
#     paths = [
#       {
#         path      = "/"
#         path_type = "Prefix"
#       }
#     ]
#   }
# ]
# observability_grafana_ingress_tls = [
#   {
#     hosts       = ["grafana.prod.example.com"]
#     secret_name = "medusa-prod-tls"
#   }
# ]
# observability_service_monitor_interval       = "15s"
# observability_service_monitor_scrape_timeout = "10s"
# observability_enable_alertmanager            = true

# IRSA bindings for the Medusa controller and workers (disabled by default).
enable_medusa_irsa = false
# medusa_irsa_controller_service_account = {
#   name = "medusa-prod-controller-irsa"
# }
# medusa_irsa_worker_service_accounts = {
#   nuclei = {
#     service_account_name = "medusa-prod-nuclei-irsa"
#   }
# }

# AWS Load Balancer Controller and Medusa ingress wiring.
enable_aws_lb_controller = true
aws_lb_controller_scheme = "internet-facing"
aws_lb_controller_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/medusa-prod-placeholder"
aws_lb_controller_additional_annotations = {
  "alb.ingress.kubernetes.io/listen-ports" = "[{\"HTTPS\":443}]"
  "alb.ingress.kubernetes.io/ssl-redirect" = "443"
}

medusa_controller_ingress_enabled = true
medusa_controller_ingress_hosts = [
  {
    host = "medusa.prod.example.com"
    paths = [
      {
        path      = "/"
        path_type = "Prefix"
      }
    ]
  }
]
medusa_controller_ingress_tls = [
  {
    hosts       = ["medusa.prod.example.com"]
    secret_name = "medusa-prod-tls"
  }
]
medusa_controller_ingress_additional_annotations = {
  "alb.ingress.kubernetes.io/load-balancer-attributes" = "idle_timeout.timeout_seconds=60"
}

vpc_cidr = "10.60.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
private_subnet_cidrs = ["10.60.1.0/24", "10.60.2.0/24", "10.60.3.0/24"]
public_subnet_cidrs = ["10.60.101.0/24", "10.60.102.0/24", "10.60.103.0/24"]

# S3 artifact storage
artifact_bucket_name                       = "medusa-prod-artifacts"
artifact_retention_days                    = 365
artifact_noncurrent_version_retention_days = 180

cluster_version = "1.29"
cluster_endpoint_public_access = false
cluster_endpoint_private_access = true
cluster_endpoint_public_access_cidrs = ["198.51.100.0/24"]
cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
cloudwatch_log_retention_in_days = 90

cluster_iam_role_additional_policy_arns = {
  security_audit = "arn:aws:iam::aws:policy/SecurityAudit"
}

node_iam_role_additional_policy_arns = {
  aws_ebs_csi        = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  aws_cni            = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  ssm_management     = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  cloudwatch_agent   = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

default_node_group_disk_size = 100

managed_node_groups = {
  general = {
    min_size = 3
    max_size = 6
    desired_size = 4
    instance_types = ["m6i.xlarge"]
    labels = {
      workload = "general"
      stage = "prod"
    }
  }

  spot = {
    min_size = 1
    max_size = 4
    desired_size = 2
    instance_types = ["m5.large"]
    capacity_type = "SPOT"
    labels = {
      workload = "burst"
      stage = "prod"
    }
    taints = [
      {
        key = "spot"
        value = "true"
        effect = "NO_SCHEDULE"
      }
    ]
  }
}

rds_instance_identifier      = "medusa-prod-db"
rds_database_name            = "medusadb"
rds_instance_class           = "db.m6i.large"
rds_allocated_storage        = 200
rds_max_allocated_storage    = 1000
rds_multi_az                 = true
rds_backup_retention_period  = 14
rds_deletion_protection      = true
rds_master_username          = "medusa_admin"
rds_master_secret_rotation_enabled = false
rds_master_secret_rotation_automatically_after_days = 30
