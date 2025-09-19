terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

locals {
  # RDS identifiers must be lowercase, alphanumeric, or hyphenated. Default to the
  # database name to keep the platform predictable.
  db_identifier          = coalesce(var.instance_identifier, var.database_name)
  max_allocated_storage  = coalesce(var.max_allocated_storage, var.allocated_storage)
  master_secret_name     = coalesce(var.master_secret_name, "${local.db_identifier}-master-credentials")
  controller_secret_tags = merge(var.tags, { "medusa:scope" = "rds-master-secret" })
  security_group_tags    = merge(var.tags, { "medusa:scope" = "rds-security-group" })
  subnet_group_tags      = merge(var.tags, { "medusa:scope" = "rds-subnet-group" })
  instance_tags          = merge(var.tags, { "medusa:scope" = "rds-instance" })
}

resource "aws_db_subnet_group" "this" {
  name        = local.db_identifier
  description = "Medusa controller database subnet group"
  subnet_ids  = var.subnet_ids

  tags = local.subnet_group_tags
}

resource "aws_security_group" "this" {
  name        = "${local.db_identifier}-sg"
  description = "Restricts RDS access to Medusa compute nodes"
  vpc_id      = var.vpc_id

  tags = local.security_group_tags
}

resource "aws_security_group_rule" "ingress_nodes" {
  for_each = toset(var.allowed_security_group_ids)

  type                     = "ingress"
  description              = "Medusa node to RDS"
  security_group_id        = aws_security_group.this.id
  from_port                = var.port
  to_port                  = var.port
  protocol                 = "tcp"
  source_security_group_id = each.value
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  security_group_id = aws_security_group.this.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

resource "random_password" "master" {
  length  = 32
  special = true
  override_special = "!#%^&*()-_=+[]{}" # Keep characters compatible with Postgres yet resistant to brute-force.
}

resource "aws_secretsmanager_secret" "master_credentials" {
  name        = local.master_secret_name
  description = coalesce(var.master_secret_description, "Master credentials for the Medusa controller database")

  kms_key_id = var.master_secret_kms_key_arn

  tags = local.controller_secret_tags

  lifecycle {
    precondition {
      condition     = !(var.master_secret_rotation_enabled && (var.master_secret_rotation_lambda_arn == null || var.master_secret_rotation_lambda_arn == ""))
      error_message = "master_secret_rotation_lambda_arn must be provided when master_secret_rotation_enabled is true."
    }
  }
}

resource "aws_db_instance" "this" {
  identifier              = local.db_identifier
  db_name                 = var.database_name
  engine                  = var.engine
  engine_version          = var.engine_version
  instance_class          = var.instance_class
  port                    = var.port
  username                = var.master_username
  password                = random_password.master.result
  allocated_storage       = var.allocated_storage
  max_allocated_storage   = local.max_allocated_storage
  storage_encrypted       = true
  kms_key_id              = var.kms_key_arn
  db_subnet_group_name    = aws_db_subnet_group.this.name
  vpc_security_group_ids  = [aws_security_group.this.id]
  multi_az                = var.multi_az
  backup_retention_period = var.backup_retention_period
  preferred_backup_window = var.preferred_backup_window
  preferred_maintenance_window = var.preferred_maintenance_window
  deletion_protection     = var.deletion_protection
  skip_final_snapshot     = var.skip_final_snapshot
  apply_immediately       = var.apply_immediately
  publicly_accessible     = false
  auto_minor_version_upgrade = true
  allow_major_version_upgrade = false
  copy_tags_to_snapshot   = true
  monitoring_interval     = var.monitoring_interval > 0 ? var.monitoring_interval : 0
  iam_database_authentication_enabled = var.iam_database_authentication_enabled
  performance_insights_enabled       = var.performance_insights_enabled
  performance_insights_kms_key_id    = var.performance_insights_enabled && var.performance_insights_kms_key_arn != null ? var.performance_insights_kms_key_arn : null

  tags = local.instance_tags
}

resource "aws_secretsmanager_secret_version" "master_credentials" {
  secret_id = aws_secretsmanager_secret.master_credentials.id

  secret_string = jsonencode({
    engine   = var.engine
    host     = aws_db_instance.this.address
    port     = aws_db_instance.this.port
    username = var.master_username
    password = random_password.master.result
    dbname   = var.database_name
    jdbc     = "jdbc:${var.engine}://${aws_db_instance.this.address}:${aws_db_instance.this.port}/${var.database_name}"
  })

  depends_on = [aws_db_instance.this]
}

resource "aws_secretsmanager_secret_rotation" "master" {
  count = var.master_secret_rotation_enabled ? 1 : 0

  secret_id          = aws_secretsmanager_secret.master_credentials.id
  rotation_lambda_arn = var.master_secret_rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.master_secret_rotation_automatically_after_days
  }
}
