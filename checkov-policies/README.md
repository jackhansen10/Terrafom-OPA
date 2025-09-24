# Checkov Policies for Terraform Security

This directory contains Checkov policies that mirror the security checks implemented in the OPA policies of this repository. These policies provide the same security validations but use Checkov's Python-based policy framework instead of OPA's Rego language.

## Policy Coverage

### RDS Security Policies (`rds_security.py`)
- **CKV_AWS_RDS_STORAGE_ENCRYPTION**: Ensures RDS instances have storage encryption enabled
- **CKV_AWS_RDS_BACKUP_RETENTION**: Validates backup retention period is at least 1 day
- **CKV_AWS_RDS_DELETION_PROTECTION**: Ensures deletion protection is enabled
- **CKV_AWS_RDS_SKIP_FINAL_SNAPSHOT**: Prevents skipping final snapshots
- **CKV_AWS_RDS_AUTO_MINOR_VERSION_UPGRADE**: Ensures auto minor version upgrades are enabled
- **CKV_AWS_RDS_PERFORMANCE_INSIGHTS**: Validates Performance Insights is enabled
- **CKV_AWS_RDS_ENHANCED_MONITORING**: Ensures enhanced monitoring is enabled
- **CKV_AWS_RDS_MANAGE_MASTER_USER_PASSWORD**: Validates Secrets Manager integration
- **CKV_AWS_RDS_SECURITY_GROUP_NO_PUBLIC_ACCESS**: Prevents public access via security groups

### S3 Security Policies (`s3_security.py`)
- **CKV_AWS_S3_SSE_KMS**: Ensures S3 buckets use KMS encryption
- **CKV_AWS_S3_BUCKET_KEY_ENABLED**: Validates Bucket Keys are enabled for SSE-KMS
- **CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_ACLS**: Ensures public ACLs are blocked
- **CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_POLICY**: Ensures public policies are blocked
- **CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_IGNORE_ACLS**: Validates public ACLs are ignored
- **CKV_AWS_S3_PUBLIC_ACCESS_BLOCK_RESTRICT_BUCKETS**: Ensures public buckets are restricted
- **CKV_AWS_S3_BUCKET_OWNER_ENFORCED**: Validates BucketOwnerEnforced ownership
- **CKV_AWS_S3_BUCKET_VERSIONING_ENABLED**: Ensures versioning is enabled
- **CKV_AWS_S3_BUCKET_LOGGING_ENABLED**: Validates server access logging is configured
- **CKV_AWS_S3_BUCKET_POLICY_DENY_INSECURE_TRANSPORT**: Ensures TLS-only transport
- **CKV_AWS_S3_BUCKET_POLICY_DENY_UNENCRYPTED_UPLOADS**: Prevents unencrypted uploads
- **CKV_AWS_S3_BUCKET_POLICY_VPCE_RESTRICTION**: Validates VPC endpoint restrictions

### DynamoDB Security Policies (`dynamodb_security.py`)
- **CKV_AWS_DYNAMODB_SSE_ENABLED**: Ensures server-side encryption is enabled
- **CKV_AWS_DYNAMODB_PITR_ENABLED**: Validates point-in-time recovery is enabled
- **CKV_AWS_DYNAMODB_DELETION_PROTECTION**: Ensures deletion protection is enabled
- **CKV_AWS_DYNAMODB_BACKUP_ENABLED**: Validates backup is enabled
- **CKV_AWS_DYNAMODB_BACKUP_RETENTION_PERIOD**: Ensures backup retention is 1-35 days
- **CKV_AWS_DYNAMODB_HASH_KEY**: Validates hash key is defined
- **CKV_AWS_DYNAMODB_HASH_KEY_ATTRIBUTE**: Ensures hash key has attribute definition
- **CKV_AWS_DYNAMODB_RANGE_KEY_ATTRIBUTE**: Validates range key attribute definitions
- **CKV_AWS_DYNAMODB_GSI_HASH_KEY_ATTRIBUTE**: Ensures GSI hash key attributes are defined
- **CKV_AWS_DYNAMODB_LSI_RANGE_KEY_ATTRIBUTE**: Validates LSI range key attributes
- **CKV_AWS_DYNAMODB_TTL_ATTRIBUTE_NAME**: Ensures TTL attribute name is specified

### KMS Security Policies (`kms_security.py`)
- **CKV_AWS_KMS_KEY_ROTATION_ENABLED**: Ensures key rotation is enabled
- **CKV_AWS_KMS_KEY_DELETION_WINDOW**: Validates deletion window is 7-30 days
- **CKV_AWS_KMS_KEY_POLICY_DEFINED**: Ensures KMS key has a policy
- **CKV_AWS_KMS_KEY_POLICY_STATEMENTS**: Validates policy has statements
- **CKV_AWS_KMS_KEY_POLICY_ROOT_ACCESS**: Ensures root account access
- **CKV_AWS_KMS_KEY_POLICY_NO_WILDCARD_ACCESS**: Prevents wildcard access
- **CKV_AWS_KMS_ALIAS_DEFINED**: Validates KMS alias exists
- **CKV_AWS_KMS_ALIAS_PREFIX**: Ensures alias starts with 'alias/'
- **CKV_AWS_CLOUDWATCH_LOG_GROUP_RETENTION**: Validates log retention period

## Usage

### Prerequisites
1. Install Checkov: `pip install checkov`
2. Ensure the `checkov-policies` directory is in your Python path

### Running Policies

#### Run all custom policies:
```bash
checkov -d . --framework terraform --external-checks-dir checkov-policies/
```

#### Run specific policy categories:
```bash
# RDS policies only
checkov -d . --framework terraform --external-checks-dir checkov-policies/ --check CKV_AWS_RDS_

# S3 policies only  
checkov -d . --framework terraform --external-checks-dir checkov-policies/ --check CKV_AWS_S3_

# DynamoDB policies only
checkov -d . --framework terraform --external-checks-dir checkov-policies/ --check CKV_AWS_DYNAMODB_

# KMS policies only
checkov -d . --framework terraform --external-checks-dir checkov-policies/ --check CKV_AWS_KMS_
```

#### Run specific policies:
```bash
checkov -d . --framework terraform --external-checks-dir checkov-policies/ --check CKV_AWS_RDS_STORAGE_ENCRYPTION,CKV_AWS_S3_SSE_KMS
```

### Integration with CI/CD

Add to your CI/CD pipeline:

```yaml
- name: Run Checkov Security Policies
  run: |
    pip install checkov
    checkov -d . --framework terraform --external-checks-dir checkov-policies/ --output cli --output junitxml --output-file-path checkov-results
```

## Policy Mapping

Each Checkov policy corresponds to a specific violation check in the OPA policies:

| OPA Policy | Checkov Policy | Description |
|------------|----------------|-------------|
| `rds_security.rego` | `rds_security.py` | RDS instance security configurations |
| `s3_security.rego` | `s3_security.py` | S3 bucket security configurations |
| `dynamodb_security.rego` | `dynamodb_security.py` | DynamoDB table security configurations |
| `kms_security.rego` | `kms_security.py` | KMS key security configurations |

## Differences from OPA Policies

1. **Input Format**: Checkov policies work directly with Terraform configuration files, while OPA policies work with Terraform plan JSON
2. **Policy Language**: Checkov uses Python, OPA uses Rego
3. **Execution**: Checkov runs during development, OPA typically runs against plans
4. **Integration**: Checkov integrates more easily with IDE plugins and CI/CD pipelines

## Contributing

When adding new policies:

1. Follow the naming convention: `CKV_AWS_SERVICE_DESCRIPTION`
2. Include proper docstrings and error messages
3. Test against both secure and insecure configurations
4. Update this README with new policy information
5. Ensure the policy is registered in `__init__.py`
