# Development environment defaults for the Medusa platform.
project_name                 = "medusa"
environment                  = "dev"
aws_profile                  = "medusa-dev"
aws_region                   = "us-east-1"
cluster_name                 = "medusa-dev"
state_bucket                 = "medusa-dev-terraform-state"
state_dynamodb_table         = "medusa-terraform-locks"
state_key_prefix             = "dev"
kubeconfig_path              = "~/.kube/config"
kubeconfig_context           = "medusa-dev"
helm_registry_config         = "~/.docker/config.json"
container_registry_server    = "ghcr.io"
container_registry_username  = "medusa-dev-bot"
container_registry_password  = "REPLACE_WITH_OIDC_TOKEN"
helm_repository_url          = "oci://ghcr.io/medusa/charts"
helm_repository_username     = "medusa-dev-bot"
helm_repository_password     = "REPLACE_WITH_OIDC_TOKEN"

# External Secrets Operator (disabled by default until the IRSA role and store are prepared).
enable_external_secrets_operator = false
external_secrets_secret_store_name = "medusa-dev-cluster-secrets"

# IRSA bindings for the Medusa controller and workers (disabled by default).
enable_medusa_irsa = false
# medusa_irsa_controller_service_account = {
#   name = "medusa-dev-controller-irsa"
# }
# medusa_irsa_worker_service_accounts = {
#   nuclei = {
#     service_account_name = "medusa-dev-nuclei-irsa"
#   }
# }

# AWS Load Balancer Controller and Medusa ingress wiring.
enable_aws_lb_controller = true
aws_lb_controller_scheme = "internal"
aws_lb_controller_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/medusa-dev-placeholder"
aws_lb_controller_additional_annotations = {
  "alb.ingress.kubernetes.io/listen-ports" = "[{\"HTTPS\":443}]"
  "alb.ingress.kubernetes.io/ssl-redirect" = "443"
}

medusa_controller_ingress_enabled = true
medusa_controller_ingress_hosts = [
  {
    host = "medusa.dev.example.com"
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
    hosts       = ["medusa.dev.example.com"]
    secret_name = "medusa-dev-tls"
  }
]
medusa_controller_ingress_additional_annotations = {
  "alb.ingress.kubernetes.io/load-balancer-attributes" = "idle_timeout.timeout_seconds=60"
}

vpc_cidr = "10.50.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b"]
private_subnet_cidrs = ["10.50.1.0/24", "10.50.2.0/24"]
public_subnet_cidrs = ["10.50.101.0/24", "10.50.102.0/24"]

# S3 artifact storage
artifact_bucket_name                           = "medusa-dev-artifacts"
artifact_bucket_force_destroy                  = true
artifact_retention_days                        = 90
artifact_noncurrent_version_retention_days     = 30

cluster_version = "1.29"
cluster_endpoint_public_access = false
cluster_endpoint_private_access = true
cluster_endpoint_public_access_cidrs = ["203.0.113.0/24"]
cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
cloudwatch_log_retention_in_days = 30

node_iam_role_additional_policy_arns = {
  aws_ebs_csi        = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  aws_cni            = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  ssm_management     = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

default_node_group_disk_size = 80

managed_node_groups = {
  general = {
    min_size = 1
    max_size = 3
    desired_size = 2
    instance_types = ["m6i.large"]
    labels = {
      workload = "general"
      stage = "dev"
    }
  }
}

rds_instance_identifier      = "medusa-dev-db"
rds_database_name            = "medusadb"
rds_instance_class           = "db.t3.medium"
rds_allocated_storage        = 50
rds_max_allocated_storage    = 200
rds_backup_retention_period  = 7
rds_deletion_protection      = false
rds_master_username          = "medusa_admin"
rds_master_secret_rotation_enabled = false
rds_master_secret_rotation_automatically_after_days = 30
