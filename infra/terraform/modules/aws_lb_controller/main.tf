terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  enabled = var.enabled

  release_base = lower(trimspace(var.release_name))
  release_slug = regexreplace(local.release_base != "" ? local.release_base : "aws-load-balancer-controller", "[^a-z0-9-]", "-")
  release_name = length(local.release_slug) > 0 ? local.release_slug : "aws-load-balancer-controller"

  service_account_name = coalesce(
    try(trimspace(var.service_account.name), null),
    local.release_name,
  )

  service_account_create = coalesce(try(var.service_account.create, null), true)
  service_account_annotations = coalesce(try(var.service_account.annotations, null), {})

  oidc_provider_path = trimsuffix(trimprefix(var.cluster_oidc_issuer_url, "https://"), "/")

  iam_role_name = coalesce(
    try(trimspace(var.iam_role_name), null),
    substr(
      regexreplace("${local.release_name}-irsa", "[^A-Za-z0-9+=,.@_-]", "-"),
      0,
      64,
    ),
  )

  load_balancer_scheme       = lower(var.load_balancer_scheme)
  load_balancer_ip_type      = lower(var.load_balancer_ip_address_type)
  target_type                = lower(var.target_type)
  ingress_class_name         = trimspace(var.ingress_class_name) != "" ? var.ingress_class_name : "alb"
  ingress_class_params_name = coalesce(
    try(trimspace(var.ingress_class_params_name), null),
    substr(
      regexreplace("${local.release_name}-ingress-params", "[^A-Za-z0-9-]", "-"),
      0,
      63,
    ),
  )

  subnet_ids = local.load_balancer_scheme == "internet-facing" ? var.public_subnet_ids : var.private_subnet_ids

  tolerations = [
    for toleration in var.tolerations : merge(
      toleration,
      contains(keys(toleration), "toleration_seconds") ? {
        tolerationSeconds = toleration.toleration_seconds
      } : {},
    )
  ]

  ingress_class_params_spec = merge(
    {
      scheme        = local.load_balancer_scheme
      ipAddressType = local.load_balancer_ip_type
    },
    length(local.subnet_ids) > 0 ? {
      subnetMappings = [
        for subnet_id in local.subnet_ids : {
          subnetID = subnet_id
        }
      ]
    } : {},
    length(var.load_balancer_security_group_ids) > 0 ? {
      securityGroups = [
        for security_group_id in var.load_balancer_security_group_ids : {
          securityGroupID = security_group_id
        }
      ]
    } : {},
    var.load_balancer_additional_tags != {} ? {
      tags = var.load_balancer_additional_tags
    } : {},
    var.vpc_id != null ? {
      vpcID = var.vpc_id
    } : {},
  )

  ingress_annotations = merge(
    {
      "kubernetes.io/ingress.class"         = local.ingress_class_name,
      "alb.ingress.kubernetes.io/scheme"    = local.load_balancer_scheme,
      "alb.ingress.kubernetes.io/target-type" = local.target_type,
    },
    var.load_balancer_ssl_policy != null && trimspace(var.load_balancer_ssl_policy) != "" ? {
      "alb.ingress.kubernetes.io/ssl-policy" = var.load_balancer_ssl_policy
    } : {},
    var.load_balancer_certificate_arn != null && trimspace(var.load_balancer_certificate_arn) != "" ? {
      "alb.ingress.kubernetes.io/certificate-arn" = var.load_balancer_certificate_arn
    } : {},
    var.load_balancer_additional_annotations,
  )

  service_account_annotations_effective = local.enabled ? merge(
    local.service_account_annotations,
    {
      "eks.amazonaws.com/role-arn" = aws_iam_role.controller[0].arn,
    },
  ) : local.service_account_annotations

  helm_base_values = local.enabled ? merge(
    {
      clusterName = var.cluster_name
      region      = var.cluster_region
      serviceAccount = {
        create      = local.service_account_create
        name        = local.service_account_name
        annotations = local.service_account_annotations_effective
      }
      nodeSelector = var.node_selector
      tolerations = [
        for toleration in local.tolerations : merge(
          omit(toleration, ["toleration_seconds"]),
          contains(keys(toleration), "tolerationSeconds") ? {
            tolerationSeconds = toleration.tolerationSeconds
          } : {},
        )
      ]
      podSecurityContext = {
        fsGroup = 65534
      }
      securityContext = {
        allowPrivilegeEscalation = false
        runAsNonRoot             = true
        runAsUser                = 65534
        runAsGroup               = 65534
        capabilities = {
          drop = ["ALL"]
        }
      }
      podDisruptionBudget = {
        create = true
      }
      ingressClassConfig = {
        create  = true
        default = var.set_default_ingress_class
        name    = local.ingress_class_name
        parameters = {
          name = local.ingress_class_params_name
        }
      }
      ingressClassParams = {
        create    = true
        name      = local.ingress_class_params_name
        namespace = var.namespace
        spec      = local.ingress_class_params_spec
      }
    },
    var.vpc_id != null ? { vpcId = var.vpc_id } : {},
  ) : {}

  helm_values = local.enabled ? concat(
    [yamlencode(local.helm_base_values)],
    [for value in var.helm_additional_values : yamlencode(value)],
  ) : []

  iam_policy_arns = toset(concat(
    ["arn:aws:iam::aws:policy/AmazonEKSLoadBalancerControllerPolicy"],
    var.additional_policy_arns,
  ))
}

data "aws_iam_policy_document" "assume" {
  count = local.enabled ? 1 : 0

  statement {
    sid     = "IRSA"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_provider_path}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_path}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_path}:sub"
      values = [
        "system:serviceaccount:${var.namespace}:${local.service_account_name}",
      ]
    }
  }
}

resource "aws_iam_role" "controller" {
  count = local.enabled ? 1 : 0

  name               = local.iam_role_name
  assume_role_policy = data.aws_iam_policy_document.assume[0].json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = local.enabled ? local.iam_policy_arns : []

  role       = aws_iam_role.controller[0].name
  policy_arn = each.value
}

resource "helm_release" "controller" {
  count = local.enabled ? 1 : 0

  name       = local.release_name
  repository = var.chart_repository
  chart      = var.chart_name
  version    = var.chart_version

  namespace        = var.namespace
  create_namespace = var.create_namespace

  values  = local.helm_values
  timeout = var.helm_timeout_seconds

  depends_on = [
    aws_iam_role_policy_attachment.managed,
  ]
}
