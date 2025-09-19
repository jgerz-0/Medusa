output "artifact_bucket" {
  description = "Artifact bucket identifiers used by Medusa components."
  value = {
    name = aws_s3_bucket.artifact.bucket
    arn  = aws_s3_bucket.artifact.arn
  }
}

output "kms_key_arn" {
  description = "KMS key ARN protecting the artifact bucket."
  value       = local.effective_kms_key_arn
}

output "prefixes" {
  description = "Normalized S3 prefixes allocated to Medusa workers."
  value       = local.worker_prefixes
}

output "controller_policy_document" {
  description = "IAM policy document granting the controller full access to artifact storage."
  value       = data.aws_iam_policy_document.controller.json
}

output "worker_policy_documents" {
  description = "IAM policy documents scoped to each worker's prefix for IRSA bindings."
  value = {
    for worker, doc in data.aws_iam_policy_document.worker :
    worker => doc.json
  }
}

output "context" {
  description = "Aggregated artifact storage metadata for downstream modules."
  value = {
    bucket = {
      name       = aws_s3_bucket.artifact.bucket
      arn        = aws_s3_bucket.artifact.arn
      kms_key_arn = local.effective_kms_key_arn
    }
    prefixes           = local.worker_prefixes
    controller_policy  = data.aws_iam_policy_document.controller.json
    worker_policies    = { for worker, doc in data.aws_iam_policy_document.worker : worker => doc.json }
  }
}
