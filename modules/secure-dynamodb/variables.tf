variable "table_name" {
  description = "Name of the DynamoDB table (must be unique within region)."
  type        = string
}

variable "billing_mode" {
  description = "Controls how you are charged for read and write throughput. Must be 'PROVISIONED' or 'PAY_PER_REQUEST'."
  type        = string
  default     = "PAY_PER_REQUEST"
  validation {
    condition     = contains(["PROVISIONED", "PAY_PER_REQUEST"], var.billing_mode)
    error_message = "Billing mode must be either 'PROVISIONED' or 'PAY_PER_REQUEST'."
  }
}

variable "read_capacity" {
  description = "Number of read capacity units for the table (required if billing_mode is PROVISIONED)."
  type        = number
  default     = null
}

variable "write_capacity" {
  description = "Number of write capacity units for the table (required if billing_mode is PROVISIONED)."
  type        = number
  default     = null
}

variable "hash_key" {
  description = "Attribute to use as the hash (partition) key."
  type        = string
}

variable "range_key" {
  description = "Attribute to use as the range (sort) key."
  type        = string
  default     = null
}

variable "attributes" {
  description = "List of nested attribute definitions. Only required for hash_key and range_key attributes."
  type = list(object({
    name = string
    type = string
  }))
}

variable "global_secondary_indexes" {
  description = "Describe a GSI for the table."
  type = list(object({
    name               = string
    hash_key           = string
    range_key          = optional(string)
    write_capacity     = number
    read_capacity      = number
    projection_type    = string
    non_key_attributes = list(string)
  }))
  default = []
}

variable "local_secondary_indexes" {
  description = "Describe an LSI on the table."
  type = list(object({
    name               = string
    range_key          = string
    projection_type    = string
    non_key_attributes = list(string)
  }))
  default = []
}

variable "kms_key_arn" {
  description = "ARN of the KMS key to use for encryption. If null, uses AWS managed key."
  type        = string
  default     = null
}

variable "point_in_time_recovery" {
  description = "Enable point-in-time recovery."
  type        = bool
  default     = true
}

variable "backup_enabled" {
  description = "Enable continuous backup."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups (1-35)."
  type        = number
  default     = 7
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 35
    error_message = "Backup retention must be between 1 and 35 days."
  }
}

variable "stream_enabled" {
  description = "Enable DynamoDB streams."
  type        = bool
  default     = false
}

variable "stream_view_type" {
  description = "When an item in the table is modified, StreamViewType determines what information is written to the stream."
  type        = string
  default     = "NEW_AND_OLD_IMAGES"
  validation {
    condition = contains([
      "KEYS_ONLY",
      "NEW_IMAGE",
      "OLD_IMAGE",
      "NEW_AND_OLD_IMAGES"
    ], var.stream_view_type)
    error_message = "Stream view type must be one of: KEYS_ONLY, NEW_IMAGE, OLD_IMAGE, NEW_AND_OLD_IMAGES."
  }
}

variable "server_side_encryption" {
  description = "Encryption at rest options."
  type = object({
    enabled     = bool
    kms_key_id  = string
  })
  default = {
    enabled    = true
    kms_key_id = null
  }
}

variable "ttl" {
  description = "Time to Live (TTL) configuration."
  type = object({
    attribute_name = string
    enabled        = bool
  })
  default = {
    attribute_name = ""
    enabled        = false
  }
}

variable "deletion_protection_enabled" {
  description = "Enable deletion protection."
  type        = bool
  default     = true
}

variable "initial_items" {
  description = "List of initial items to populate the table with (JSON format)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to the DynamoDB table."
  type        = map(string)
  default     = {}
}
