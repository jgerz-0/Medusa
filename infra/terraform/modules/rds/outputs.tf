output "security_group_id" {
  description = "Security group restricting access to the controller database."
  value       = aws_security_group.this.id
}

output "subnet_group_name" {
  description = "Subnet group backing the controller database."
  value       = aws_db_subnet_group.this.name
}

output "database_identifier" {
  description = "Identifier of the provisioned RDS instance."
  value       = aws_db_instance.this.id
}

output "master_credentials_secret_arn" {
  description = "Secrets Manager ARN storing the master credentials."
  value       = aws_secretsmanager_secret.master_credentials.arn
}

output "controller_context" {
  description = "Structured connection details consumed by the Medusa controller."
  value = {
    hostname = aws_db_instance.this.address
    port     = aws_db_instance.this.port
    database = var.database_name
    connection_string = format(
      "postgresql://%s:{{resolve:secretsmanager:%s:SecretString:password}}@%s:%d/%s",
      var.master_username,
      aws_secretsmanager_secret.master_credentials.arn,
      aws_db_instance.this.address,
      aws_db_instance.this.port,
      var.database_name,
    )
    secret_arn  = aws_secretsmanager_secret.master_credentials.arn
    secret_name = aws_secretsmanager_secret.master_credentials.name
    rotation = var.master_secret_rotation_enabled ? {
      enabled                   = true
      rotation_lambda_arn       = var.master_secret_rotation_lambda_arn
      automatically_after_days  = var.master_secret_rotation_automatically_after_days
      rotation_id               = aws_secretsmanager_secret_rotation.master[0].id
    } : {
      enabled                   = false
      rotation_lambda_arn       = null
      automatically_after_days  = null
      rotation_id               = null
    }
  }
}
