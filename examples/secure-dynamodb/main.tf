variable "table_name" {
  description = "Name of the DynamoDB table"
  type        = string
  default     = "secure-example-table"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "dev"
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN for encryption"
  type        = string
  default     = null
}

module "secure_dynamodb" {
  source = "../../modules/secure-dynamodb"

  table_name = var.table_name
  hash_key   = "id"
  
  attributes = [
    {
      name = "id"
      type = "S"
    },
    {
      name = "email"
      type = "S"
    },
    {
      name = "created_at"
      type = "N"
    }
  ]

  global_secondary_indexes = [
    {
      name            = "EmailIndex"
      hash_key        = "email"
      write_capacity  = 5
      read_capacity   = 5
      projection_type = "ALL"
      non_key_attributes = []
    }
  ]

  kms_key_arn = var.kms_key_arn
  point_in_time_recovery = true
  backup_enabled = true
  backup_retention_days = 7
  stream_enabled = false
  deletion_protection_enabled = true

  ttl = {
    attribute_name = "expires_at"
    enabled        = false
  }

  initial_items = [
    jsonencode({
      id         = { S = "user-001" }
      email      = { S = "user@example.com" }
      created_at = { N = "1640995200" }
    })
  ]

  tags = {
    Environment = var.environment
    Owner       = "security"
    Purpose     = "example-database"
  }
}

output "table_id" {
  description = "DynamoDB table ID"
  value       = module.secure_dynamodb.table_id
}

output "table_arn" {
  description = "DynamoDB table ARN"
  value       = module.secure_dynamodb.table_arn
}

output "table_name" {
  description = "DynamoDB table name"
  value       = module.secure_dynamodb.table_name
}
