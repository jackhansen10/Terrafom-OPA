variable "key_alias" {
  description = "KMS key alias (must start with 'alias/')"
  type        = string
  default     = "alias/example-secure-key"
}

variable "description" {
  description = "Description for the KMS key"
  type        = string
  default     = "Example secure KMS key for encryption"
}

variable "allowed_principals" {
  description = "List of ARNs allowed to use the key"
  type        = list(string)
  default     = []
}

variable "allowed_services" {
  description = "List of AWS services allowed to use the key"
  type        = list(string)
  default     = ["s3.amazonaws.com"]
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "dev"
}

module "secure_kms_key" {
  source = "../../modules/secure-kms-key"

  key_alias           = var.key_alias
  description         = var.description
  deletion_window_in_days = 30
  enable_key_rotation = true
  key_usage           = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region        = false
  allowed_principals  = var.allowed_principals
  allowed_services    = var.allowed_services
  enable_cloudtrail_logging = true

  tags = {
    Environment = var.environment
    Owner       = "security"
    Purpose     = "example-encryption"
  }
}

output "key_id" {
  description = "KMS key ID"
  value       = module.secure_kms_key.key_id
}

output "key_arn" {
  description = "KMS key ARN"
  value       = module.secure_kms_key.key_arn
}

output "alias_name" {
  description = "KMS key alias name"
  value       = module.secure_kms_key.alias_name
}

output "alias_arn" {
  description = "KMS key alias ARN"
  value       = module.secure_kms_key.alias_arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group for KMS audit logs"
  value       = module.secure_kms_key.cloudwatch_log_group_name
}
