variable "bucket_name" {
  description = "Logging bucket name (globally unique)."
  type        = string
}

variable "force_destroy" {
  description = "Allow deletion with objects (use carefully)."
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "Optional KMS CMK ARN for SSE-KMS. If null, use AES256 (SSE-S3)."
  type        = string
  default     = null
}

variable "retention_days" {
  description = "Retention period for log objects before expiration. Set null to disable."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags to apply."
  type        = map(string)
  default     = {}
}
