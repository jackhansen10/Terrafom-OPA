# Terraform Secure S3 Bucket Templates

This repository provides a reusable Terraform module for creating a secure-by-default Amazon S3 bucket aligned with SOC 2, PCI DSS, ISO 27001, and NIST CSF best practices, plus an example to get started quickly.

## Repository Structure

- `modules/secure-s3-bucket/` – Reusable module with secure S3 configuration
- `examples/secure-s3-bucket/` – Example usage that can be applied directly

## Quickstart

1. Clone the repo and change directory:

```bash
git clone <your-repo-url>
cd Terrafom-OPA/examples/secure-s3-bucket
```

2. Provide values (either via CLI or `terraform.tfvars`):

```hcl
aws_region          = "us-east-1"
bucket_name         = "your-unique-bucket-name"
logging_bucket_name = "your-unique-logs-bucket-name"
# kms_key_alias     = "alias/your-bucket-kms" # optional
# restrict_to_vpc_endpoint_ids = ["vpce-0123456789abcdef0"]
```

3. Initialize and apply:

```bash
terraform init
terraform plan
terraform apply
```

## How to Deploy Your Own Secure S3 Bucket

### Option A: Use the included example (recommended to start)

1. Ensure AWS credentials are configured (one of):
   - Environment vars: `AWS_PROFILE` or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN` if using MFA)
   - Or `~/.aws/credentials` with a named profile
2. In `examples/secure-s3-bucket`, set inputs via `terraform.tfvars` or CLI `-var` flags.
3. Run `terraform init && terraform apply`.
4. Outputs will show your bucket and KMS ARNs.

### Option B: Consume the module from another root

Create a new directory (or use an existing Terraform root) and add:

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" { type = string }

module "secure_bucket" {
  source = "github.com/your-org/your-repo//modules/secure-s3-bucket?ref=v1.0.0"

  bucket_name                     = var.bucket_name
  logging_bucket_name             = var.logging_bucket_name
  kms_key_alias                   = "alias/my-secure-bucket-kms"
  restrict_to_vpc_endpoint_ids    = []

  tags = {
    Environment = "prod"
    Owner       = "security"
  }
}

variable "bucket_name" { type = string }
variable "logging_bucket_name" { type = string }
```

Then run:

```bash
terraform init
terraform apply -var "aws_region=us-east-1" -var "bucket_name=my-unique-bucket" -var "logging_bucket_name=my-unique-bucket-logs"
```

### Passing variables

- `terraform.tfvars` file in your working directory (preferred)
- CLI: `-var key=value` or `-var-file=path/to/file.tfvars`
- Environment: `TF_VAR_bucket_name`, `TF_VAR_logging_bucket_name`, etc.

### Clean up

Destroy resources when done (careful with `force_destroy` if you enabled it):

```bash
terraform destroy
```

## Compliance Features

- Default encryption using a customer-managed KMS key with rotation
- Public access fully blocked with S3 Public Access Block
- Versioning enabled; lifecycle retention for noncurrent versions
- Server access logging to a dedicated logs bucket with least-privilege ACL
- TLS-only and KMS-encryption-required bucket policies
- Optional restriction to specific VPC endpoint IDs

See `modules/secure-s3-bucket/README.md` for more details and control mapping.

## Centralized Logging

- `modules/logging-bucket/`: Create a secure logging bucket (ACL/log-delivery-write, public blocked, optional KMS, lifecycle retention).
- `modules/logging-registry/`: Select a logging bucket from `registry/logging-buckets.json` by account and region.

### Registry JSON formats

Nested or flat formats are supported. See `modules/logging-registry/README.md` for examples.

### Example: auto-select logging bucket

```bash
cd Terrafom-OPA/examples/secure-s3-bucket-with-registry
terraform init
terraform apply -var "aws_region=us-east-1" -var "bucket_name=my-unique-bucket"
```

This will read `../../registry/logging-buckets.json` and automatically pass the selected logging bucket name into the secure S3 module.

## Modules Overview

- `modules/secure-s3-bucket`: Primary secure bucket (SSE-KMS, versioning, lifecycle, TLS-only, encryption-required, optional VPCE restriction) and sends server access logs to the provided logging bucket name.
- `modules/logging-bucket`: Hardened logging target bucket supporting SSE-S3 or SSE-KMS and optional retention.
- `modules/logging-registry`: Resolves a logging bucket name for the current account and region from a JSON registry file.

## OPA Policy Validation

Policies are provided in `policy/` to validate Terraform plans before applying.

1) Generate a plan JSON:
```bash
cd examples/secure-s3-bucket
terraform init
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

2) Validate with Conftest (recommended):
```bash
conftest test tfplan.json --policy ../policy
```

Or with OPA directly:
```bash
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.s3.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.s3.security.allow"
```

## Troubleshooting

- Bucket name must be globally unique: adjust `bucket_name` and `logging_bucket_name`.
- Logging bucket ACL: S3 server access logging requires the target bucket to have `log-delivery-write` ACL; use `modules/logging-bucket` or ensure equivalent configuration.
- KMS permissions: Ensure identities writing to the bucket can use the CMK and that the bucket policy enforces the intended CMK.
- Lifecycle rule warnings: Provider may require a `filter {}` on lifecycle rules. This repo already includes it; if you copy/paste rules, include `filter {}` to apply to all objects.
- VPCE restriction: If you enable VPCE restriction, ensure callers access S3 via the allowed VPC endpoints.
