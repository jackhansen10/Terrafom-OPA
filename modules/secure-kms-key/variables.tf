variable "key_alias" {
  description = "Display name for the KMS key alias. Must start with 'alias/'."
  type        = string
}

variable "description" {
  description = "Description of the KMS key."
  type        = string
  default     = "Secure KMS key for encryption"
}

variable "deletion_window_in_days" {
  description = "Waiting period for scheduled key deletion (7-30 days)."
  type        = number
  default     = 30
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "Deletion window must be between 7 and 30 days."
  }
}

variable "enable_key_rotation" {
  description = "Enable automatic key rotation (recommended for compliance)."
  type        = bool
  default     = true
}

variable "key_usage" {
  description = "Intended use of the key. Must be 'ENCRYPT_DECRYPT' or 'SIGN_VERIFY'."
  type        = string
  default     = "ENCRYPT_DECRYPT"
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY"], var.key_usage)
    error_message = "Key usage must be either 'ENCRYPT_DECRYPT' or 'SIGN_VERIFY'."
  }
}

variable "customer_master_key_spec" {
  description = "Specifies whether the key contains a symmetric key or an asymmetric key pair."
  type        = string
  default     = "SYMMETRIC_DEFAULT"
  validation {
    condition = contains([
      "SYMMETRIC_DEFAULT",
      "RSA_2048", "RSA_3072", "RSA_4096",
      "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521",
      "ECC_SECG_P256K1"
    ], var.customer_master_key_spec)
    error_message = "Invalid customer master key spec."
  }
}

variable "multi_region" {
  description = "Whether the key is a multi-region key."
  type        = bool
  default     = false
}

variable "bypass_policy_lockout_safety_check" {
  description = "Skip safety check for policy lockout (not recommended)."
  type        = bool
  default     = false
}

variable "key_policy" {
  description = "Custom key policy JSON. If null, a default secure policy will be created."
  type        = string
  default     = null
}

variable "allowed_principals" {
  description = "List of ARNs/identifiers allowed to use the key (for default policy)."
  type        = list(string)
  default     = []
}

variable "allowed_services" {
  description = "List of AWS services allowed to use the key (e.g., ['s3.amazonaws.com'])."
  type        = list(string)
  default     = []
}

variable "enable_cloudtrail_logging" {
  description = "Enable CloudTrail logging for key usage (recommended for audit)."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to the KMS key."
  type        = map(string)
  default     = {}
}
