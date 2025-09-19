terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  vpc_name = coalesce(var.vpc_name, "${var.cluster_name}-vpc")

  default_node_group = {
    capacity_type = "ON_DEMAND"
    disk_size = var.default_node_group_disk_size
  }

  managed_node_groups = {
    for name, cfg in var.managed_node_groups :
    name => merge(
      local.default_node_group,
      {
        min_size = cfg.min_size
        max_size = cfg.max_size
        desired_size = cfg.desired_size
        instance_types = cfg.instance_types
        capacity_type = coalesce(try(cfg.capacity_type, null), local.default_node_group.capacity_type)
        disk_size = coalesce(try(cfg.disk_size, null), local.default_node_group.disk_size)
        labels = try(cfg.labels, {})
        taints = try(cfg.taints, [])
        subnet_ids = try(cfg.subnet_ids, [])
        iam_role_additional_policies = merge(
          var.node_iam_role_additional_policy_arns,
          try(cfg.additional_policy_arns, {})
        )
      },
      {
        tags = merge(var.tags, try(cfg.tags, {}))
      }
    )
  }
}

resource "aws_kms_key" "eks" {
  description = "Medusa EKS secrets encryption key"
  deletion_window_in_days = 30
  enable_key_rotation = true

  tags = merge(var.tags, {
    "medusa:scope" = "eks-kms"
  })
}

resource "aws_kms_alias" "eks" {
  name = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.1"

  name = local.vpc_name
  cidr = var.vpc_cidr

  azs = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets = var.public_subnet_cidrs

  enable_dns_support = true
  enable_dns_hostnames = true

  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags = merge(var.tags, {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb" = 1
  })

  private_subnet_tags = merge(var.tags, {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb" = 1
  })

  tags = merge(var.tags, {
    "medusa:scope" = "eks-vpc"
  })
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name = var.cluster_name
  cluster_version = var.cluster_version

  cluster_endpoint_private_access = var.cluster_endpoint_private_access
  cluster_endpoint_public_access = var.cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  cluster_enabled_log_types = var.cluster_log_types
  create_cloudwatch_log_group = true
  cloudwatch_log_group_retention_in_days = var.cloudwatch_log_retention_in_days

  vpc_id = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  cluster_iam_role_name = var.cluster_iam_role_name
  cluster_iam_role_use_name_prefix = var.cluster_iam_role_name == null
  cluster_iam_role_additional_policies = var.cluster_iam_role_additional_policy_arns

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"
    capacity_type = local.default_node_group.capacity_type
    disk_size = local.default_node_group.disk_size
    iam_role_name = var.node_iam_role_name
    iam_role_use_name_prefix = var.node_iam_role_name == null
    iam_role_additional_policies = var.node_iam_role_additional_policy_arns
    subnet_ids = module.vpc.private_subnets
  }

  eks_managed_node_groups = {
    for name, cfg in local.managed_node_groups :
    name => merge(
      cfg.subnet_ids != [] ? { subnet_ids = cfg.subnet_ids } : {},
      {
        min_size = cfg.min_size
        max_size = cfg.max_size
        desired_size = cfg.desired_size
        instance_types = cfg.instance_types
        capacity_type = cfg.capacity_type
        disk_size = cfg.disk_size
        labels = cfg.labels
        taints = cfg.taints
        iam_role_additional_policies = cfg.iam_role_additional_policies
        tags = cfg.tags
      }
    )
  }

  cluster_encryption_config = [
    {
      resources = ["secrets"]
      provider_key_arn = aws_kms_key.eks.arn
    }
  ]

  cluster_security_group_tags = merge(var.tags, {
    "medusa:scope" = "eks-cluster-sg"
  })

  node_security_group_tags = merge(var.tags, {
    "medusa:scope" = "eks-node-sg"
  })

  tags = merge(var.tags, {
    "medusa:scope" = "eks-cluster"
  })
}
