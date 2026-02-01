variable "trail_name" {
  description = "Name of the CloudTrail trail."
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs (globally unique)."
  type        = string
}

variable "s3_key_prefix" {
  description = "Optional prefix for CloudTrail log objects."
  type        = string
  default     = "cloudtrail"
}

variable "force_destroy" {
  description = "Whether to allow destroying the logs bucket even if it contains objects."
  type        = bool
  default     = false
}

variable "kms_key_alias" {
  description = "KMS key alias for CloudTrail log encryption (must start with 'alias/')."
  type        = string
  default     = "alias/cloudtrail-logs"
}

variable "kms_deletion_window_in_days" {
  description = "KMS key deletion window in days (7-30)."
  type        = number
  default     = 30
}

variable "enable_log_file_validation" {
  description = "Enable CloudTrail log file validation."
  type        = bool
  default     = true
}

variable "is_multi_region_trail" {
  description = "Create a multi-region trail."
  type        = bool
  default     = true
}

variable "include_global_service_events" {
  description = "Include global service events (e.g., IAM)."
  type        = bool
  default     = true
}

variable "is_organization_trail" {
  description = "Create an organization trail (requires AWS Organizations)."
  type        = bool
  default     = false
}

variable "enable_cloudwatch_logging" {
  description = "Send CloudTrail events to CloudWatch Logs."
  type        = bool
  default     = true
}

variable "cloudwatch_log_group_retention_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
  default     = 90
}

variable "s3_log_expiration_days" {
  description = "Optional expiration in days for CloudTrail log objects."
  type        = number
  default     = null
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}
