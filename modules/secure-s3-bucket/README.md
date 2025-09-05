# Secure S3 Bucket Module

Creates an S3 bucket with security-hardening suitable for SOC 2, PCI DSS, ISO 27001, and NIST CSF environments.

## Inputs

- `bucket_name` (string) – Primary bucket name (globally unique)
- `logging_bucket_name` (string) – Logs bucket name (globally unique)
- `force_destroy` (bool) – Allow deletion with objects; default `false`
- `kms_key_alias` (string) – KMS key alias; default `alias/s3-default-kms`
- `kms_deletion_window_in_days` (number) – 7-30; default `30`
- `object_expiration_days` (number|null) – Optional current object expiration (not applied by default)
- `noncurrent_version_expiration_days` (number) – default `90`
- `restrict_to_vpc_endpoint_ids` (list(string)) – Optional allowed VPC endpoints
- `tags` (map(string)) – Tags applied to all resources

## Outputs

- `bucket_id`
- `bucket_arn`
- `kms_key_arn`

## Features

- SSE-KMS with customer-managed key and rotation
- S3 Public Access Block set to block all public access
- BucketOwnerEnforced ownership (no ACLs) for primary bucket
- Access logging to a dedicated logs bucket with required ACL
- TLS-only access via policy
- Deny unencrypted uploads and enforce CMK
- Optional restriction to specified VPC endpoint IDs
- Lifecycle rules: abort incomplete multipart, expire noncurrent versions

## Notes

- MFA Delete requires manual configuration and is not supported via Terraform
- Consider enabling S3 Object Lock for WORM/retention requirements if needed
- Enable CloudTrail S3 Data Events for object-level audit logging

## Control Mapping (non-exhaustive)

- SOC 2 CC6/CC7: Access controls, logging, encryption
- PCI DSS 4.0 3.x/7.x/10.x: Cryptographic storage, access control, logging
- ISO 27001 A.8/A.10/A.12/A.13: Asset protection, cryptography, operations security, communications security
- NIST CSF PR.AC, PR.DS: Access control and data security
