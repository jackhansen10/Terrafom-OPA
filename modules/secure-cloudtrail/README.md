# Secure CloudTrail Module

Creates a secure AWS CloudTrail trail with encrypted S3 storage and optional CloudWatch Logs delivery, aligned with SOC 2, PCI DSS, ISO 27001, and NIST CSF expectations.

## Features

- Encrypted CloudTrail log storage using a customer-managed KMS key
- S3 bucket hardened with public access blocks and optional retention
- Log file validation enabled by default
- Multi-region trail with global service events
- Optional CloudWatch Logs integration for near-real-time monitoring
- Least-privilege bucket and KMS policies for CloudTrail delivery

## Inputs

- `trail_name` (string) – CloudTrail trail name
- `s3_bucket_name` (string) – S3 bucket name for CloudTrail logs
- `s3_key_prefix` (string) – Optional log prefix; default `cloudtrail`
- `force_destroy` (bool) – Allow destroying log bucket with objects; default `false`
- `kms_key_alias` (string) – KMS key alias; default `alias/cloudtrail-logs`
- `kms_deletion_window_in_days` (number) – 7-30; default `30`
- `enable_log_file_validation` (bool) – default `true`
- `is_multi_region_trail` (bool) – default `true`
- `include_global_service_events` (bool) – default `true`
- `is_organization_trail` (bool) – default `false`
- `enable_cloudwatch_logging` (bool) – default `true`
- `cloudwatch_log_group_retention_days` (number) – default `90`
- `s3_log_expiration_days` (number|null) – Optional object expiration; default `null`
- `tags` (map(string)) – default `{}`

## Outputs

- `trail_name`, `trail_arn`
- `s3_bucket_name`, `s3_bucket_arn`
- `kms_key_arn`
- `cloudwatch_log_group_name`

## Compliance Features

- **Audit Logging**: CloudTrail management event logging with validation
- **Data Protection**: KMS-encrypted logs and controlled S3 access
- **Access Control**: Bucket policies restricted to CloudTrail service
- **Monitoring**: Optional CloudWatch Logs for alerting and analytics

## Control Mapping (non-exhaustive)

- **SOC 2 CC7.1/CC7.2**: Continuous monitoring and log integrity
- **PCI DSS 10.x**: Audit trail logging and retention
- **ISO 27001 A.12.4/A.16**: Event logging and incident response
- **NIST CSF DE.AE/DE.CM**: Detection and continuous monitoring

## Usage Example

```hcl
module "secure_cloudtrail" {
  source = "../../modules/secure-cloudtrail"

  trail_name     = "org-trail"
  s3_bucket_name = "my-cloudtrail-logs-bucket"

  tags = {
    Environment = "prod"
    Owner       = "security"
  }
}
```
