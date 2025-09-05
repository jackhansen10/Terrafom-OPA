output "bucket_id" {
  description = "ID of the primary S3 bucket"
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN of the primary S3 bucket"
  value       = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for default encryption"
  value       = aws_kms_key.s3.arn
}
