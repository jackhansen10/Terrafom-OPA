output "key_id" {
  description = "The globally unique identifier for the key"
  value       = aws_kms_key.this.key_id
}

output "key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = aws_kms_key.this.arn
}

output "alias_name" {
  description = "The display name of the alias"
  value       = aws_kms_alias.this.name
}

output "alias_arn" {
  description = "The Amazon Resource Name (ARN) of the key alias"
  value       = aws_kms_alias.this.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for KMS audit logs (if enabled)"
  value       = var.enable_cloudtrail_logging ? aws_cloudwatch_log_group.kms_logs[0].name : null
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for KMS audit logs (if enabled)"
  value       = var.enable_cloudtrail_logging ? aws_cloudwatch_log_group.kms_logs[0].arn : null
}
