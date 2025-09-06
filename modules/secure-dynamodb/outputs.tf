output "table_id" {
  description = "ID of the DynamoDB table"
  value       = aws_dynamodb_table.this.id
}

output "table_arn" {
  description = "ARN of the DynamoDB table"
  value       = aws_dynamodb_table.this.arn
}

output "table_name" {
  description = "Name of the DynamoDB table"
  value       = aws_dynamodb_table.this.name
}

output "table_stream_arn" {
  description = "ARN of the DynamoDB table stream"
  value       = aws_dynamodb_table.this.stream_arn
}

output "table_stream_label" {
  description = "A timestamp, in ISO 8601 format, for this stream"
  value       = aws_dynamodb_table.this.stream_label
}

output "table_hash_key" {
  description = "Hash key of the DynamoDB table"
  value       = aws_dynamodb_table.this.hash_key
}

output "table_range_key" {
  description = "Range key of the DynamoDB table"
  value       = aws_dynamodb_table.this.range_key
}

output "table_billing_mode" {
  description = "Billing mode of the DynamoDB table"
  value       = aws_dynamodb_table.this.billing_mode
}

output "table_read_capacity" {
  description = "Read capacity of the DynamoDB table"
  value       = aws_dynamodb_table.this.read_capacity
}

output "table_write_capacity" {
  description = "Write capacity of the DynamoDB table"
  value       = aws_dynamodb_table.this.write_capacity
}
