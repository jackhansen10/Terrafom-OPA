# OPA Policies for Secure S3 Configuration

This directory contains Rego policies to validate that the Terraform plan for the S3 bucket enforces security best practices: SSE-KMS, public access blocks, versioning, access logging, TLS-only, and encryption-required bucket policies.

## Prerequisites

- Terraform >= 1.5
- Either `opa` or `conftest` CLI installed

## Generate a Terraform plan JSON

```bash
cd examples/secure-s3-bucket
terraform init
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

## Evaluate with conftest (recommended)

```bash
conftest test tfplan.json --policy ../policy
```

- Conftest will fail if any `deny` rules match.
- For more detail:

```bash
conftest verify --policy ../policy
conftest test tfplan.json --policy ../policy -o json
```

## Evaluate with OPA directly

```bash
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.s3.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.s3.security.allow"
```

- `violations` returns a list of objects with `msg`, `suggestion`, and `resource`. `allow` is true when there are zero violations.

## What is checked

- SSE-KMS enabled and Bucket Keys enabled
- S3 Public Access Block: all four booleans true
- Ownership controls: `BucketOwnerEnforced`
- Versioning enabled
- Server access logging configured to a target bucket
- Bucket policy contains `DenyInsecureTransport` and `DenyUnEncryptedObjectUploads`
- If present, VPC endpoint restriction statement enforces `aws:sourceVpce`

