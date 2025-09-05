module "secure_bucket" {
  source = "../../modules/secure-s3-bucket"

  bucket_name                     = var.bucket_name
  logging_bucket_name             = var.logging_bucket_name
  force_destroy                   = false
  kms_key_alias                   = var.kms_key_alias
  kms_deletion_window_in_days     = 30
  noncurrent_version_expiration_days = 90
  restrict_to_vpc_endpoint_ids    = var.restrict_to_vpc_endpoint_ids

  tags = {
    Environment = var.environment
    Owner       = "security"
  }
}

variable "environment" {
  description = "Environment tag (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "bucket_name" {
  description = "Primary bucket name (globally unique)"
  type        = string
}

variable "logging_bucket_name" {
  description = "Access logs bucket name (globally unique)"
  type        = string
}

variable "kms_key_alias" {
  description = "Alias to assign to the KMS key"
  type        = string
  default     = "alias/example-secure-bucket"
}

variable "restrict_to_vpc_endpoint_ids" {
  description = "Optional list of allowed VPC endpoint IDs"
  type        = list(string)
  default     = []
}

output "bucket_id" {
  value = module.secure_bucket.bucket_id
}

output "bucket_arn" {
  value = module.secure_bucket.bucket_arn
}

output "kms_key_arn" {
  value = module.secure_bucket.kms_key_arn
}
