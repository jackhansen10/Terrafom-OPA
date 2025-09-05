# Logging Bucket Module

Creates a secure S3 bucket suitable as a target for server access logs and other service logs.

## Features

- Public access fully blocked
- Ownership set to BucketOwnerPreferred
- Required `log-delivery-write` ACL for S3 server access logs
- SSE-KMS (if `kms_key_arn` provided) or SSE-S3 by default
- Optional lifecycle expiration for logs (default 365 days)

## Inputs

- `bucket_name` (string)
- `force_destroy` (bool) – default `false`
- `kms_key_arn` (string|null) – default `null`
- `retention_days` (number|null) – default `365`
- `tags` (map(string)) – default `{}`

## Outputs

- `bucket_id`, `bucket_arn`
