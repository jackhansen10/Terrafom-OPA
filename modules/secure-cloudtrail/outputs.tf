output "trail_name" {
  description = "CloudTrail trail name."
  value       = aws_cloudtrail.this.name
}

output "trail_arn" {
  description = "CloudTrail trail ARN."
  value       = aws_cloudtrail.this.arn
}

output "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail.id
}

output "s3_bucket_arn" {
  description = "S3 bucket ARN for CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail.arn
}

output "kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudTrail logs."
  value       = aws_kms_key.cloudtrail.arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name (if enabled)."
  value       = var.enable_cloudwatch_logging ? aws_cloudwatch_log_group.cloudtrail[0].name : null
}
