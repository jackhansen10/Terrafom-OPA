# Secure DynamoDB Module

Creates a secure AWS DynamoDB table with compliance features aligned with SOC 2, PCI DSS, ISO 27001, and NIST CSF requirements.

## Features

- Encryption at rest with KMS (customer-managed or AWS-managed keys)
- Point-in-time recovery enabled by default
- Continuous backup with configurable retention
- DynamoDB streams support for real-time data processing
- Time-to-Live (TTL) support for automatic data expiration
- Deletion protection to prevent accidental data loss
- Support for both provisioned and on-demand billing
- Global and local secondary indexes
- Initial data population support

## Inputs

- `table_name` (string) – Name of the DynamoDB table (must be unique within region)
- `billing_mode` (string) – 'PROVISIONED' or 'PAY_PER_REQUEST'; default 'PAY_PER_REQUEST'
- `read_capacity` (number|null) – Read capacity units (required for PROVISIONED)
- `write_capacity` (number|null) – Write capacity units (required for PROVISIONED)
- `hash_key` (string) – Attribute to use as the hash (partition) key
- `range_key` (string|null) – Attribute to use as the range (sort) key
- `attributes` (list) – List of attribute definitions
- `global_secondary_indexes` (list) – GSI configurations; default []
- `local_secondary_indexes` (list) – LSI configurations; default []
- `kms_key_arn` (string|null) – KMS key ARN for encryption; default null (AWS-managed)
- `point_in_time_recovery` (bool) – Enable PITR; default true
- `backup_enabled` (bool) – Enable continuous backup; default true
- `backup_retention_days` (number) – Backup retention (1-35 days); default 7
- `stream_enabled` (bool) – Enable DynamoDB streams; default false
- `stream_view_type` (string) – Stream view type; default 'NEW_AND_OLD_IMAGES'
- `server_side_encryption` (object) – Encryption configuration; default enabled with AWS-managed key
- `ttl` (object) – TTL configuration; default disabled
- `deletion_protection_enabled` (bool) – Enable deletion protection; default true
- `initial_items` (list(string)) – Initial table items (JSON format); default []
- `tags` (map(string)) – Tags to apply; default {}

## Outputs

- `table_id`, `table_arn`, `table_name`
- `table_stream_arn`, `table_stream_label`
- `table_hash_key`, `table_range_key`
- `table_billing_mode`, `table_read_capacity`, `table_write_capacity`

## Compliance Features

- **Encryption at Rest**: KMS encryption with customer-managed or AWS-managed keys
- **Backup & Recovery**: Point-in-time recovery and continuous backup
- **Data Protection**: Deletion protection and lifecycle management
- **Access Control**: IAM-based access control (configure separately)
- **Audit Logging**: CloudTrail integration for API calls
- **Data Integrity**: Streams for real-time data validation

## Control Mapping

- **SOC 2 CC6.1/CC6.6**: Access controls and data protection
- **PCI DSS 3.x/4.x**: Encryption and secure data storage
- **ISO 27001 A.8/A.10/A.12**: Asset protection, cryptography, operations security
- **NIST CSF PR.DS**: Data security and protection

## Usage Example

```hcl
module "secure_dynamodb" {
  source = "../../modules/secure-dynamodb"

  table_name = "secure-user-data"
  hash_key   = "user_id"
  
  attributes = [
    {
      name = "user_id"
      type = "S"
    },
    {
      name = "email"
      type = "S"
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

  kms_key_arn = module.secure_kms_key.key_arn
  
  tags = {
    Environment = "prod"
    Owner       = "security"
  }
}
```
