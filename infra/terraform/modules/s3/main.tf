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
  bucket_base_name = (
    var.artifact_bucket_name != null ? var.artifact_bucket_name :
    var.artifact_bucket_prefix != null ? "${var.artifact_bucket_prefix}-${var.environment}" :
    "${var.project_name}-${var.environment}-${var.artifact_bucket_suffix}"
  )

  bucket_name = replace(lower(local.bucket_base_name), "_", "-")

  controller_object_actions = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:GetObjectTagging",
    "s3:PutObjectTagging",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
  ]

  worker_object_actions = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:GetObjectTagging",
    "s3:PutObjectTagging",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
  ]

  worker_prefixes_raw = {
    for worker, cfg in var.worker_access :
    worker => regexreplace(trimspace(cfg.prefix), "^/+", "")
  }

  worker_rules = {
    for worker, prefix in local.worker_prefixes_raw :
    worker => {
      prefix       = prefix == "" ? "" : (endswith(prefix, "/") ? prefix : "${prefix}/")
      allow_delete = try(var.worker_access[worker].allow_delete, true)
    }
  }

  lifecycle_enabled = var.enable_artifact_expiration || var.enable_noncurrent_version_expiration || var.abort_incomplete_multipart_upload_days != null
}

# Optionally create a dedicated KMS key so security engineers control encryption boundaries.
resource "aws_kms_key" "artifact" {
  count = var.kms_key_arn == null && var.create_kms_key ? 1 : 0

  description             = "KMS key encrypting Medusa artifact storage"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = true

  tags = merge(var.tags, {
    "medusa:scope" = "artifacts-kms"
  })
}

resource "aws_kms_alias" "artifact" {
  count = length(aws_kms_key.artifact) == 1 ? 1 : 0

  name          = coalesce(var.kms_key_alias, "alias/${local.bucket_name}-artifacts")
  target_key_id = aws_kms_key.artifact[0].key_id
}

# Primary artifact bucket storing scan outputs with strict ownership controls.
resource "aws_s3_bucket" "artifact" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.tags, {
    "medusa:scope" = "artifacts"
  })
}

resource "aws_s3_bucket_versioning" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

# Enforce default KMS encryption with bucket keys for cost-effective SSE.
resource "aws_s3_bucket_server_side_encryption_configuration" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn != null ? var.kms_key_arn : aws_kms_key.artifact[0].arn
    }

    bucket_key_enabled = true
  }
}

# Block any public ACLs or policies; artifact data must stay private.
resource "aws_s3_bucket_public_access_block" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifact" {
  count  = local.lifecycle_enabled ? 1 : 0
  bucket = aws_s3_bucket.artifact.id

  rule {
    id     = "artifacts-retention"
    status = "Enabled"

    filter {
      prefix = ""
    }

    dynamic "expiration" {
      for_each = var.enable_artifact_expiration ? [1] : []

      content {
        days = var.artifact_retention_days
      }
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.enable_noncurrent_version_expiration ? [1] : []

      content {
        noncurrent_days = var.noncurrent_version_retention_days
      }
    }

    dynamic "abort_incomplete_multipart_upload" {
      for_each = var.abort_incomplete_multipart_upload_days != null ? [1] : []

      content {
        days_after_initiation = var.abort_incomplete_multipart_upload_days
      }
    }
  }
}

data "aws_iam_policy_document" "bucket_enforcement" {
  statement {
    sid = "DenyInsecureTransport"

    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.artifact.arn,
      "${aws_s3_bucket.artifact.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# Deny insecure (non-TLS) access to eliminate downgrade attacks.
resource "aws_s3_bucket_policy" "artifact" {
  bucket = aws_s3_bucket.artifact.id
  policy = data.aws_iam_policy_document.bucket_enforcement.json
}

data "aws_iam_policy_document" "controller" {
  statement {
    sid = "List"

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:ListBucketMultipartUploads",
    ]

    resources = [aws_s3_bucket.artifact.arn]
  }

  statement {
    sid = "Objects"

    actions = local.controller_object_actions

    resources = [
      "${aws_s3_bucket.artifact.arn}/*",
    ]
  }
}

data "aws_iam_policy_document" "worker" {
  for_each = local.worker_rules

  statement {
    sid = "ScopedList"

    actions = ["s3:ListBucket"]

    resources = [aws_s3_bucket.artifact.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${each.value.prefix}*"]
    }
  }

  statement {
    sid = "ScopedObjects"

    actions = each.value.allow_delete ? concat(local.worker_object_actions, ["s3:DeleteObject"]) : local.worker_object_actions

    resources = [
      "${aws_s3_bucket.artifact.arn}/${each.value.prefix}*",
    ]
  }
}

locals {
  effective_kms_key_arn = var.kms_key_arn != null ? var.kms_key_arn : aws_kms_key.artifact[0].arn

  worker_prefixes = {
    for worker, cfg in local.worker_rules :
    worker => cfg.prefix
  }
}
