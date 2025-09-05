output "bucket_id" {
  description = "Logging bucket ID"
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "Logging bucket ARN"
  value       = aws_s3_bucket.this.arn
}
