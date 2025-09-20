terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  release_base_raw = regexreplace(lower(var.release_name), "[^a-z0-9-]", "-")
  release_base_trimmed = regexreplace(regexreplace(local.release_base_raw, "^-+", ""), "-+$", "")
  release_slug = substr(local.release_base_trimmed, 0, min(length(local.release_base_trimmed), 40))

  oidc_provider_path = trimsuffix(trimprefix(var.cluster_oidc_issuer_url, "https://"), "/")

  controller_role_name_candidate = regexreplace("${local.release_slug}-controller-irsa", "[^A-Za-z0-9+=,.@_-]", "-")
  controller_role_name = substr(
    local.controller_role_name_candidate,
    0,
    min(length(local.controller_role_name_candidate), 64),
  )

  controller_service_account_candidate = regexreplace(
    lower("${local.release_slug}-controller-irsa"),
    "[^a-z0-9-]",
    "-",
  )
  controller_service_account_default = regexreplace(
    substr(
      local.controller_service_account_candidate,
      0,
      min(length(local.controller_service_account_candidate), 63),
    ),
    "-+$",
    "",
  )

  controller_config = {
    create      = try(var.controller_service_account.create, true)
    annotations = try(var.controller_service_account.annotations, {})
    name = coalesce(
      try(var.controller_service_account.name, null),
      local.controller_service_account_default,
    )
    role_name = coalesce(
      try(var.controller_service_account.role_name, null),
      local.controller_role_name,
    )
  }

  worker_parts = {
    for worker, _ in var.worker_policy_documents :
    worker => [for part in split("_", lower(worker)) : part]
  }

  worker_helm_keys = {
    for worker, parts in local.worker_parts :
    worker => (
      length(parts) == 0
      ? worker
      : join(
          "",
          concat(
            [lower(parts[0])],
            [for part in slice(parts, 1, length(parts)) : title(part)],
          ),
        )
    )
  }

  worker_role_names = {
    for worker, _ in var.worker_policy_documents :
    worker => substr(
      regexreplace("${local.release_slug}-${worker}-irsa", "[^A-Za-z0-9+=,.@_-]", "-"),
      0,
      min(length(regexreplace("${local.release_slug}-${worker}-irsa", "[^A-Za-z0-9+=,.@_-]", "-")), 64),
    )
  }

  worker_service_account_defaults = {
    for worker, _ in var.worker_policy_documents :
    worker => regexreplace(
      substr(
        regexreplace(
          lower("${local.release_slug}-worker-${lookup(local.worker_helm_keys, worker, worker)}-sa"),
          "[^a-z0-9-]",
          "-",
        ),
        0,
        min(
          length(
            regexreplace(
              lower("${local.release_slug}-worker-${lookup(local.worker_helm_keys, worker, worker)}-sa"),
              "[^a-z0-9-]",
              "-",
            )
          ),
          63,
        ),
      ),
      "-+$",
      "",
    )
  }

  worker_configs = {
    for worker, policy in var.worker_policy_documents :
    worker => {
      helm_worker_key      = coalesce(try(var.worker_service_accounts[worker].helm_worker_key, null), local.worker_helm_keys[worker])
      service_account_name = coalesce(try(var.worker_service_accounts[worker].service_account_name, null), local.worker_service_account_defaults[worker])
      role_name            = coalesce(try(var.worker_service_accounts[worker].role_name, null), local.worker_role_names[worker])
      create               = try(var.worker_service_accounts[worker].create, true)
      enabled              = try(var.worker_service_accounts[worker].enabled, true)
      annotations          = try(var.worker_service_accounts[worker].annotations, {})
      policy               = policy
    }
  }

  enabled_worker_configs = {
    for worker, cfg in local.worker_configs :
    worker => cfg if cfg.enabled
  }
}

data "aws_iam_policy_document" "controller_assume_role" {
  count = var.enabled ? 1 : 0

  statement {
    sid    = "IRSAControllerTrust"
    effect = "Allow"

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
        "system:serviceaccount:${var.namespace}:${local.controller_config.name}",
      ]
    }
  }
}

data "aws_iam_policy_document" "worker_assume_role" {
  for_each = var.enabled ? local.enabled_worker_configs : {}

  statement {
    sid    = "IRSAWorkerTrust"
    effect = "Allow"

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
        "system:serviceaccount:${var.namespace}:${each.value.service_account_name}",
      ]
    }
  }
}

resource "aws_iam_role" "controller" {
  count = var.enabled ? 1 : 0

  name               = local.controller_config.role_name
  assume_role_policy = data.aws_iam_policy_document.controller_assume_role[0].json
  description        = "Medusa controller IRSA role"

  tags = merge(var.tags, {
    "medusa:component" = "controller"
  })
}

resource "aws_iam_role_policy" "controller" {
  count = var.enabled ? 1 : 0

  name   = "${local.controller_config.role_name}-inline"
  role   = aws_iam_role.controller[0].id
  policy = var.controller_policy_document
}

resource "aws_iam_role" "worker" {
  for_each = var.enabled ? local.enabled_worker_configs : {}

  name               = each.value.role_name
  assume_role_policy = data.aws_iam_policy_document.worker_assume_role[each.key].json
  description        = "Medusa ${each.key} worker IRSA role"

  tags = merge(var.tags, {
    "medusa:component" = "worker"
    "medusa:worker"    = each.key
  })
}

resource "aws_iam_role_policy" "worker" {
  for_each = var.enabled ? local.enabled_worker_configs : {}

  name   = "${each.value.role_name}-inline"
  role   = aws_iam_role.worker[each.key].id
  policy = each.value.policy
}

locals {
  controller_output = var.enabled && length(aws_iam_role.controller) == 1 ? {
    role_name              = aws_iam_role.controller[0].name
    role_arn               = aws_iam_role.controller[0].arn
    policy_name            = aws_iam_role_policy.controller[0].name
    service_account_name   = local.controller_config.name
    service_account_create = local.controller_config.create
    annotations = merge(
      local.controller_config.annotations,
      {
        "eks.amazonaws.com/role-arn" = aws_iam_role.controller[0].arn,
      },
    )
  } : null

  worker_outputs = var.enabled ? {
    for worker, role in aws_iam_role.worker :
    worker => {
      role_name              = role.name
      role_arn               = role.arn
      policy_name            = aws_iam_role_policy.worker[worker].name
      helm_worker_key        = local.enabled_worker_configs[worker].helm_worker_key
      service_account_name   = local.enabled_worker_configs[worker].service_account_name
      service_account_create = local.enabled_worker_configs[worker].create
      annotations = merge(
        local.enabled_worker_configs[worker].annotations,
        {
          "eks.amazonaws.com/role-arn" = role.arn,
        },
      )
    }
  } : {}

  helm_values = (
    var.enabled && local.controller_output != null
  ) ? [
    {
      controller = {
        serviceAccount = {
          create      = local.controller_output.service_account_create
          name        = local.controller_output.service_account_name
          annotations = local.controller_output.annotations
        }
      }
      workers = {
        for worker, cfg in local.worker_outputs :
        cfg.helm_worker_key => {
          serviceAccount = {
            create      = cfg.service_account_create
            name        = cfg.service_account_name
            annotations = cfg.annotations
          }
        }
      }
    }
  ] : []
}
