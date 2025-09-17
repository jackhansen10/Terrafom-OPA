# DynamoDB Table
resource "aws_dynamodb_table" "this" {
  name           = var.table_name
  billing_mode   = var.billing_mode
  read_capacity  = var.read_capacity
  write_capacity = var.write_capacity
  hash_key       = var.hash_key
  range_key      = var.range_key

  dynamic "attribute" {
    for_each = var.attributes
    content {
      name = attribute.value.name
      type = attribute.value.type
    }
  }

  dynamic "global_secondary_index" {
    for_each = var.global_secondary_indexes
    content {
      name               = global_secondary_index.value.name
      hash_key           = global_secondary_index.value.hash_key
      range_key          = global_secondary_index.value.range_key
      write_capacity     = global_secondary_index.value.write_capacity
      read_capacity      = global_secondary_index.value.read_capacity
      projection_type    = global_secondary_index.value.projection_type
      non_key_attributes = global_secondary_index.value.non_key_attributes
    }
  }

  dynamic "local_secondary_index" {
    for_each = var.local_secondary_indexes
    content {
      name               = local_secondary_index.value.name
      range_key          = local_secondary_index.value.range_key
      projection_type    = local_secondary_index.value.projection_type
      non_key_attributes = local_secondary_index.value.non_key_attributes
    }
  }

  # Encryption at rest
  dynamic "server_side_encryption" {
    for_each = var.server_side_encryption.enabled ? [1] : []
    content {
      enabled      = true
      kms_key_arn  = var.server_side_encryption.kms_key_id != null ? var.server_side_encryption.kms_key_id : var.kms_key_arn
    }
  }


  # Point-in-time recovery
  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  # Continuous backup (handled via backup_retention_period)

  # DynamoDB streams
  stream_enabled = var.stream_enabled
  stream_view_type = var.stream_enabled ? var.stream_view_type : null

  # Time to Live
  dynamic "ttl" {
    for_each = var.ttl.enabled ? [1] : []
    content {
      attribute_name = var.ttl.attribute_name
      enabled        = true
    }
  }

  # Deletion protection (handled via lifecycle)

  tags = merge(var.tags, {
    Name = var.table_name
    Purpose = "secure-database"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# DynamoDB Table Item (optional - for initial data)
resource "aws_dynamodb_table_item" "this" {
  count = length(var.initial_items) > 0 ? length(var.initial_items) : 0
  
  table_name = aws_dynamodb_table.this.name
  hash_key   = aws_dynamodb_table.this.hash_key
  range_key  = aws_dynamodb_table.this.range_key

  item = var.initial_items[count.index]
}

# Backup policy for automated backups
# Note: DynamoDB continuous backups are managed via the backup block in the table resource
