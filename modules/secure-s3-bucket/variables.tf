variable "bucket_name" {
  description = "Name of the primary S3 bucket. Must be globally unique."
  type        = string
}

variable "logging_bucket_name" {
  description = "Name for the S3 access logging bucket. Must be globally unique."
  type        = string
}

variable "force_destroy" {
  description = "Allow Terraform to delete bucket with non-empty contents (not recommended for production)."
  type        = bool
  default     = false
}

variable "kms_key_alias" {
  description = "Alias to assign to the KMS key used for S3 encryption."
  type        = string
  default     = "alias/s3-default-kms"
}

variable "kms_deletion_window_in_days" {
  description = "Waiting period for scheduled KMS key deletion (7-30)."
  type        = number
  default     = 30
}

variable "object_expiration_days" {
  description = "Number of days after which CURRENT objects transition or expire. Use null to disable."
  type        = number
  default     = null
}

variable "noncurrent_version_expiration_days" {
  description = "Days to retain noncurrent object versions before expiration."
  type        = number
  default     = 90
}

variable "restrict_to_vpc_endpoint_ids" {
  description = "Optional list of VPC endpoint IDs allowed to access the bucket. Empty disables restriction."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}
