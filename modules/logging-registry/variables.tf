variable "registry_path" {
  description = "Path to JSON file mapping accounts/regions to logging buckets."
  type        = string
}

variable "account_id" {
  description = "AWS account ID override. If null, derived via data source."
  type        = string
  default     = null
}

variable "region" {
  description = "AWS region override. If null, derived via data source."
  type        = string
  default     = null
}
