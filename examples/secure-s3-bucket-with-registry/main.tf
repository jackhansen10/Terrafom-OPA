variable "bucket_name" {
  description = "Primary bucket name (globally unique)"
  type        = string
}

variable "registry_path" {
  description = "Path to logging bucket registry JSON"
  type        = string
  default     = "../../registry/logging-buckets.json"
}

module "logging_registry" {
  source        = "../../modules/logging-registry"
  registry_path = var.registry_path
}

module "secure_bucket" {
  source = "../../modules/secure-s3-bucket"

  bucket_name                     = var.bucket_name
  logging_bucket_name             = module.logging_registry.bucket_name
  kms_key_alias                   = "alias/example-secure-bucket"
  noncurrent_version_expiration_days = 90

  tags = {
    Environment = "dev"
    Owner       = "security"
  }
}

output "bucket_id" {
  value = module.secure_bucket.bucket_id
}

output "logging_bucket" {
  value = module.logging_registry.bucket_name
}
