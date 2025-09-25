# Terraform Secure Infrastructure Templates

**Author:** Jack Hansen  
**License:** MIT License (see [LICENSE](LICENSE))  
**Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md)

This repository provides reusable Terraform modules for creating secure-by-default AWS infrastructure aligned with SOC 2, PCI DSS, ISO 27001, and NIST CSF best practices. Includes modules for S3, KMS, DynamoDB, RDS, and EKS with comprehensive security validation using OPA and Checkov policies.

## License & Attribution

This project is licensed under the MIT License. When using this code, please:
- Include the original copyright notice and license
- Provide attribution to the original author (Jack Hansen)
- Link back to this repository when possible

## Repository Structure

- `modules/secure-s3-bucket/` – Reusable module with secure S3 configuration
- `modules/secure-kms-key/` – Reusable module with secure KMS key configuration
- `modules/secure-dynamodb/` – Reusable module with secure DynamoDB configuration
- `modules/secure-rds/` – Reusable module with secure RDS configuration
- `modules/secure-eks/` – Reusable module with secure EKS cluster configuration
- `modules/logging-bucket/` – Centralized logging bucket module
- `modules/logging-registry/` – Registry for auto-selecting logging buckets
- `examples/secure-s3-bucket/` – Example usage that can be applied directly
- `examples/secure-s3-bucket-with-registry/` – Example with auto-logging bucket selection
- `examples/secure-kms-key/` – Example KMS key usage
- `examples/secure-dynamodb/` – Example DynamoDB usage
- `examples/secure-rds/` – Example RDS usage
- `examples/secure-eks/` – Example secure EKS cluster usage
- `examples/insecure-eks/` – Example insecure EKS cluster for policy testing
- `policy/` – OPA policies for security validation
- `checkov-policies/` – Checkov policies for security validation
- `test-plans/` – Sample Terraform plans for policy testing

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

## How to Deploy Your Own Secure Infrastructure

### Option A: Use the included examples (recommended to start)

1. Ensure AWS credentials are configured (one of):
   - Environment vars: `AWS_PROFILE` or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN` if using MFA)
   - Or `~/.aws/credentials` with a named profile

2. Choose your service and navigate to the example directory:
   - **S3**: `examples/secure-s3-bucket/`
   - **KMS**: `examples/secure-kms-key/`
   - **DynamoDB**: `examples/secure-dynamodb/`
   - **RDS**: `examples/secure-rds/`
   - **EKS**: `examples/secure-eks/`

3. Set inputs via `terraform.tfvars` or CLI `-var` flags, then run `terraform init && terraform apply`.

4. Outputs will show your resource ARNs and connection details.

### Option B: Consume modules from another root

Create a new directory (or use an existing Terraform root) and add the appropriate module:

**S3 Bucket:**
```hcl
module "secure_bucket" {
  source = "github.com/your-org/your-repo//modules/secure-s3-bucket?ref=v1.0.0"
  # ... module configuration
}
```

**KMS Key:**
```hcl
module "secure_kms" {
  source = "github.com/your-org/your-repo//modules/secure-kms-key?ref=v1.0.0"
  # ... module configuration
}
```

**DynamoDB Table:**
```hcl
module "secure_dynamodb" {
  source = "github.com/your-org/your-repo//modules/secure-dynamodb?ref=v1.0.0"
  # ... module configuration
}
```

**RDS Instance:**
```hcl
module "secure_rds" {
  source = "github.com/your-org/your-repo//modules/secure-rds?ref=v1.0.0"
  # ... module configuration
}
```

**EKS Cluster:**
```hcl
module "secure_eks" {
  source = "github.com/your-org/your-repo//modules/secure-eks?ref=v1.0.0"
  # ... module configuration
}
```

Then run `terraform init && terraform apply` with appropriate variables.

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

### S3 Bucket Security
- Default encryption using a customer-managed KMS key with rotation
- Public access fully blocked with S3 Public Access Block
- Versioning enabled; lifecycle retention for noncurrent versions
- Server access logging to a dedicated logs bucket with least-privilege ACL
- TLS-only and KMS-encryption-required bucket policies
- Optional restriction to specific VPC endpoint IDs

### KMS Key Security
- Automatic key rotation enabled by default
- Secure key policy with least privilege access
- Support for symmetric and asymmetric keys
- Multi-region key support
- CloudTrail logging integration
- CloudWatch log group for audit trails
- Configurable deletion window (7-30 days)

### DynamoDB Security
- Encryption at rest with KMS (customer-managed or AWS-managed keys)
- Point-in-time recovery enabled by default
- Continuous backup with configurable retention
- DynamoDB streams support for real-time data processing
- Time-to-Live (TTL) support for automatic data expiration
- Deletion protection to prevent accidental data loss
- Support for both provisioned and on-demand billing

### RDS Security
- Encryption at rest with KMS (customer-managed or AWS-managed keys)
- Automated backups with configurable retention
- Point-in-time recovery support
- Enhanced monitoring and Performance Insights
- CloudWatch logs export
- Deletion protection and final snapshots
- Password management via AWS Secrets Manager
- Secure networking with VPC and security groups

### EKS Security
- Encryption at rest using AWS KMS with key rotation
- Private endpoint access with no public access
- Complete audit logging (API, audit, authenticator, controller manager, scheduler)
- Security groups with least privilege access
- OIDC provider for IRSA (IAM Roles for Service Accounts)
- AWS Load Balancer Controller integration
- CloudWatch container insights for monitoring
- Pod Security Standards and Network Policies
- Resource quotas and proper scaling configurations
- Latest supported Kubernetes versions

See individual module READMEs for detailed control mapping to SOC 2, PCI DSS, ISO 27001, and NIST CSF.

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
- `modules/secure-kms-key`: Secure KMS key with rotation, least-privilege policies, CloudTrail logging, and compliance features.
- `modules/secure-dynamodb`: Secure DynamoDB table with encryption, backup, point-in-time recovery, deletion protection, and compliance features.
- `modules/secure-rds`: Secure RDS instance with encryption, backup, monitoring, Performance Insights, deletion protection, and compliance features.
- `modules/secure-eks`: Secure EKS cluster with encryption at rest, private endpoint access, audit logging, security groups, OIDC provider, and compliance features.
- `modules/logging-bucket`: Hardened logging target bucket supporting SSE-S3 or SSE-KMS and optional retention.
- `modules/logging-registry`: Resolves a logging bucket name for the current account and region from a JSON registry file.

## OPA Policy Validation

Policies are provided in `policy/` to validate Terraform plans before applying.

### S3 Security Validation
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

### KMS Security Validation
1) Generate a plan JSON:
```bash
cd examples/secure-kms-key
terraform init
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

2) Validate with Conftest:
```bash
conftest test tfplan.json --policy ../policy
```

### DynamoDB Security Validation
1) Generate a plan JSON:
```bash
cd examples/secure-dynamodb
terraform init
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

2) Validate with Conftest:
```bash
conftest test tfplan.json --policy ../policy
```

### RDS Security Validation
1) Generate a plan JSON:
```bash
cd examples/secure-rds
terraform init
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

2) Validate with Conftest:
```bash
conftest test tfplan.json --policy ../policy
```

### EKS Security Validation
1) Generate a plan JSON:
```bash
cd examples/secure-eks
terraform init
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

2) Validate with Conftest:
```bash
conftest test tfplan.json --policy ../policy
```

### Direct OPA Evaluation
```bash
# S3 policies
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.s3.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.s3.security.allow"

# KMS policies
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.kms.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.kms.security.allow"

# DynamoDB policies
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.dynamodb.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.dynamodb.security.allow"

# RDS policies
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.rds.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.rds.security.allow"

# EKS policies
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.eks.security.violations"
opa eval -f pretty -d ../policy -i tfplan.json "data.terraform.eks.security.allow"
```

### Testing with Sample Plans
The repository includes sample Terraform plan files for testing OPA policies:

```bash
# Test S3 policy with sample plans
opa eval -f pretty -d policy/s3_security.rego -i test-plans/s3/secure/s3-bucket-secure-plan.json "data.terraform.s3.security.allow"
opa eval -f pretty -d policy/s3_security.rego -i test-plans/s3/insecure/s3-bucket-insecure-plan.json "data.terraform.s3.security.violations"

# Test DynamoDB policy with sample plans
opa eval -f pretty -d policy/dynamodb_security.rego -i test-plans/dynamodb/secure/dynamodb-table-secure-plan.json "data.terraform.dynamodb.security.allow"
opa eval -f pretty -d policy/dynamodb_security.rego -i test-plans/dynamodb/insecure/dynamodb-table-insecure-plan.json "data.terraform.dynamodb.security.violations"

# Test RDS policy with sample plans
opa eval -f pretty -d policy/rds_security.rego -i test-plans/rds/secure/rds-instance-secure-plan.json "data.terraform.rds.security.allow"
opa eval -f pretty -d policy/rds_security.rego -i test-plans/rds/insecure/rds-instance-insecure-plan.json "data.terraform.rds.security.violations"

# Test KMS policy with sample plans
opa eval -f pretty -d policy/kms_security.rego -i test-plans/kms/secure/kms-key-secure-plan.json "data.terraform.kms.security.allow"
opa eval -f pretty -d policy/kms_security.rego -i test-plans/kms/insecure/kms-key-insecure-plan.json "data.terraform.kms.security.violations"

# Test EKS policy with sample plans
opa eval -f pretty -d policy/eks_security.rego -i test-plans/eks/secure/eks-cluster-secure-plan.json "data.terraform.eks.security.allow"
opa eval -f pretty -d policy/eks_security.rego -i test-plans/eks/insecure/eks-cluster-insecure-plan.json "data.terraform.eks.security.violations"
```

See `test-plans/README.md` for detailed information about the sample plans and expected results.

## Checkov Policy Validation

Checkov provides real-time security validation during development and integrates easily with CI/CD pipelines. This repository includes custom Checkov policies that mirror the OPA policies.

### Installation

Install Checkov using pipx (recommended):
```bash
# Install pipx if not already installed
brew install pipx
pipx ensurepath

# Install Checkov
pipx install checkov

# Verify installation
checkov --version
```

### Running Checkov Evaluations

#### Basic Usage
```bash
# Run all custom policies against an example
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true

# Run specific policy categories
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_S3_

# Run with different output formats
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --output json --output-file-path results.json
```

#### Service-Specific Evaluations

**S3 Security Validation:**
```bash
# Test secure S3 configuration
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_S3_

# Test insecure S3 configuration (should show violations)
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_S3_
```

**KMS Security Validation:**
```bash
# Test secure KMS configuration
checkov -d examples/secure-kms-key/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_KMS_
```

**DynamoDB Security Validation:**
```bash
# Test secure DynamoDB configuration
checkov -d examples/secure-dynamodb/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_DYNAMODB_
```

**RDS Security Validation:**
```bash
# Test secure RDS configuration
checkov -d examples/secure-rds/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_RDS_
```

**EKS Security Validation:**
```bash
# Test secure EKS configuration
checkov -d examples/secure-eks/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_EKS_

# Test insecure EKS configuration (should show violations)
checkov -d examples/insecure-eks/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_EKS_
```

#### Advanced Usage

**Run All Custom Policies:**
```bash
# Run all 57 custom policies across all services
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --run-all-external-checks
```

**CI/CD Integration:**
```bash
# Generate JUnit XML for CI/CD pipelines
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --output junitxml --output-file-path checkov-results.xml

# Generate SARIF for GitHub Security tab
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --output sarif --output-file-path checkov-results.sarif
```

**Skip Specific Checks:**
```bash
# Skip specific policies if needed
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --skip-check CKV_AWS_S3_BUCKET_LOGGING_ENABLED
```

### Policy Coverage

The custom Checkov policies provide comprehensive coverage:

- **S3 Policies (12)**: Encryption, public access blocking, versioning, logging, policies
- **KMS Policies (9)**: Key rotation, deletion windows, policies, aliases, logging
- **DynamoDB Policies (11)**: Encryption, backup, PITR, deletion protection, attributes
- **RDS Policies (9)**: Encryption, backup, monitoring, deletion protection, Secrets Manager
- **EKS Policies (16)**: Encryption, logging, endpoint access, node groups, security groups

**Total: 57 Custom Checkov Policies**

### Testing Policy Validation

Validate that policies work correctly:

```bash
# Test policy structure
python3 checkov-policies/validate_policies.py

# Test against secure configurations (should pass)
checkov -d examples/secure-s3-bucket/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_S3_

# Test against insecure configurations (should show violations)
checkov -d examples/insecure-eks/ --framework terraform --external-checks-dir checkov-policies/ --download-external-modules true --check CKV_AWS_EKS_
```

### External Module Flag

The `--download-external-modules true` flag is crucial for examples that use external Terraform modules (like `terraform-aws-modules/vpc/aws`). This flag:

- Downloads external modules from the Terraform Registry
- Analyzes the downloaded modules for security issues
- Includes module resources in the security scan
- Provides comprehensive coverage of the entire infrastructure

### IDE Integration

Checkov integrates with popular IDEs:

- **VS Code**: Install the Checkov extension
- **IntelliJ/PyCharm**: Install the Checkov plugin
- **Vim/Neovim**: Use checkov.vim plugin

### GitHub Actions Integration

```yaml
name: Security Validation
on: [push, pull_request]

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: examples/secure-s3-bucket/
          framework: terraform
          external_checks_dir: checkov-policies/
          download_external_modules: true
          output_format: sarif
          output_file_path: checkov-results.sarif
```

## Troubleshooting

### S3 Issues
- Bucket name must be globally unique: adjust `bucket_name` and `logging_bucket_name`.
- Logging bucket ACL: S3 server access logging requires the target bucket to have `log-delivery-write` ACL; use `modules/logging-bucket` or ensure equivalent configuration.
- KMS permissions: Ensure identities writing to the bucket can use the CMK and that the bucket policy enforces the intended CMK.
- Lifecycle rule warnings: Provider may require a `filter {}` on lifecycle rules. This repo already includes it; if you copy/paste rules, include `filter {}` to apply to all objects.
- VPCE restriction: If you enable VPCE restriction, ensure callers access S3 via the allowed VPC endpoints.

### KMS Issues
- Key alias must start with 'alias/': ensure your alias follows AWS naming conventions.
- Key policy permissions: Verify that principals and services in `allowed_principals` and `allowed_services` have the necessary KMS permissions.
- Deletion window: Keys cannot be deleted immediately; the deletion window provides a safety period.
- CloudTrail logging: Ensure CloudTrail is configured to log KMS events for audit compliance.
- Key rotation: Automatic rotation creates new key material while preserving the same key ID and alias.

### DynamoDB Issues
- Table name must be unique within the region: adjust `table_name` if conflicts occur.
- Attribute definitions: Ensure all hash keys, range keys, and index keys have corresponding attribute definitions.
- Capacity planning: For PROVISIONED billing mode, set appropriate read/write capacity based on expected load.
- Backup retention: Backup retention is limited to 1-35 days; adjust `backup_retention_days` accordingly.
- Deletion protection: Disable deletion protection before destroying the table, or use `terraform destroy -target` with caution.
- TTL configuration: When enabling TTL, ensure the specified attribute exists and contains numeric timestamps.

### RDS Issues
- Instance identifier must be unique: adjust `identifier` if conflicts occur.
- Subnet group: Ensure subnet IDs are in different AZs for high availability.
- Security groups: Verify security group rules allow appropriate database access.
- Backup retention: Backup retention is limited to 0-35 days; adjust `backup_retention_period` accordingly.
- Deletion protection: Disable deletion protection before destroying the instance, or use `terraform destroy -target` with caution.
- Password management: When using Secrets Manager, retrieve passwords from AWS Secrets Manager console or CLI.
- Performance Insights: Requires additional cost; disable if not needed for compliance.

### EKS Issues
- **Cluster name must be unique**: Adjust `cluster_name` if conflicts occur.
- **Subnet configuration**: Ensure at least 2 subnets in different AZs for high availability.
- **Security groups**: Verify security group rules allow appropriate cluster and node communication.
- **Node group scaling**: Ensure `min_size` is at least 2 for high availability.
- **External modules**: Use `--download-external-modules true` flag with Checkov for VPC module analysis.
- **OIDC provider**: Ensure OIDC provider is created before using IRSA (IAM Roles for Service Accounts).
- **Load balancer controller**: Install AWS Load Balancer Controller for production workloads.
- **Pod Security Standards**: Configure appropriate security contexts for workloads.
- **Network policies**: Implement network policies to restrict pod-to-pod communication.
- **Helm provider**: Ensure Helm provider is properly configured for addon management.
- **Kubernetes provider**: Configure Kubernetes provider with cluster endpoint and auth.
- **VPC requirements**: EKS requires VPC with DNS support and hostnames enabled.
- **IAM permissions**: Ensure sufficient permissions for EKS service role and node group role.
- **Addon conflicts**: Some addons may conflict; use `resolve_conflicts` parameter if needed.
- **PodSecurityPolicy deprecation**: Use Pod Security Standards for Kubernetes 1.21+ clusters.
