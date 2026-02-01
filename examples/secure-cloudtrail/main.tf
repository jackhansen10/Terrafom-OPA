module "secure_cloudtrail" {
  source = "../../modules/secure-cloudtrail"

  trail_name     = var.trail_name
  s3_bucket_name = var.s3_bucket_name
  kms_key_alias  = var.kms_key_alias

  tags = {
    Environment = var.environment
    Owner       = "security"
  }
}

variable "environment" {
  description = "Environment tag (e.g., dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "trail_name" {
  description = "CloudTrail trail name."
  type        = string
  default     = "secure-cloudtrail"
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs (globally unique)."
  type        = string
}

variable "kms_key_alias" {
  description = "Alias to assign to the KMS key."
  type        = string
  default     = "alias/cloudtrail-logs"
}

output "trail_arn" {
  value = module.secure_cloudtrail.trail_arn
}

output "s3_bucket_name" {
  value = module.secure_cloudtrail.s3_bucket_name
}
