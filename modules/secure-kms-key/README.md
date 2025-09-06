# Secure KMS Key Module

Creates a secure AWS KMS key with compliance features aligned with SOC 2, PCI DSS, ISO 27001, and NIST CSF requirements.

## Features

- Automatic key rotation enabled by default
- Secure key policy with least privilege access
- Support for symmetric and asymmetric keys
- Multi-region key support
- CloudTrail logging integration
- CloudWatch log group for audit trails
- Configurable deletion window (7-30 days)
- Service and principal-based access controls

## Inputs

- `key_alias` (string) – Display name for the key alias (must start with 'alias/')
- `description` (string) – Key description; default "Secure KMS key for encryption"
- `deletion_window_in_days` (number) – 7-30 days; default 30
- `enable_key_rotation` (bool) – Enable automatic rotation; default true
- `key_usage` (string) – 'ENCRYPT_DECRYPT' or 'SIGN_VERIFY'; default 'ENCRYPT_DECRYPT'
- `customer_master_key_spec` (string) – Key spec; default 'SYMMETRIC_DEFAULT'
- `multi_region` (bool) – Multi-region key; default false
- `bypass_policy_lockout_safety_check` (bool) – Skip safety check; default false
- `key_policy` (string|null) – Custom policy JSON; default null (uses secure default)
- `allowed_principals` (list(string)) – ARNs allowed to use key; default []
- `allowed_services` (list(string)) – Services allowed to use key; default []
- `enable_cloudtrail_logging` (bool) – Enable CloudTrail logging; default true
- `tags` (map(string)) – Tags to apply; default {}

## Outputs

- `key_id`, `key_arn`, `alias_name`, `alias_arn`
- `cloudwatch_log_group_name`, `cloudwatch_log_group_arn` (if logging enabled)

## Compliance Features

- **Key Rotation**: Automatic rotation for cryptographic key management
- **Access Control**: Least privilege policy with explicit principal/service allowlists
- **Audit Logging**: CloudTrail integration and CloudWatch log groups
- **Key Management**: Secure deletion window and multi-region support
- **Encryption**: Support for both symmetric and asymmetric encryption

## Control Mapping

- **SOC 2 CC6.1/CC6.6**: Access controls and encryption key management
- **PCI DSS 3.x**: Cryptographic key management and rotation
- **ISO 27001 A.10/A.12**: Cryptographic controls and key management
- **NIST CSF PR.DS**: Data security and cryptographic protection

## Usage Example

```hcl
module "secure_kms_key" {
  source = "../../modules/secure-kms-key"

  key_alias           = "alias/my-secure-key"
  description         = "KMS key for application encryption"
  allowed_principals  = ["arn:aws:iam::123456789012:role/MyRole"]
  allowed_services    = ["s3.amazonaws.com", "rds.amazonaws.com"]
  
  tags = {
    Environment = "prod"
    Owner       = "security"
  }
}
```
