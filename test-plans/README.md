# Test Plans Directory

This directory contains sample Terraform plan JSON files for testing OPA policies against different AWS resource configurations.

## Directory Structure

```
test-plans/
├── s3/
│   ├── secure/
│   │   └── s3-bucket-secure-plan.json
│   └── insecure/
│       └── s3-bucket-insecure-plan.json
├── dynamodb/
│   ├── secure/
│   │   └── dynamodb-table-secure-plan.json
│   └── insecure/
│       └── dynamodb-table-insecure-plan.json
├── rds/
│   ├── secure/
│   │   └── rds-instance-secure-plan.json
│   └── insecure/
│       └── rds-instance-insecure-plan.json
└── kms/
    ├── secure/
    │   └── kms-key-secure-plan.json
    └── insecure/
        └── kms-key-insecure-plan.json
```

## File Naming Convention

- **Resource Type**: `s3-bucket`, `dynamodb-table`, `rds-instance`, `kms-key`
- **Configuration Type**: `secure` or `insecure`
- **File Type**: `plan.json`

## Usage Examples

### Test S3 Policy
```bash
# Test secure S3 configuration
opa eval -f pretty -d policy/s3_security.rego -i test-plans/s3/secure/s3-bucket-secure-plan.json "data.terraform.s3.security.allow"

# Test insecure S3 configuration
opa eval -f pretty -d policy/s3_security.rego -i test-plans/s3/insecure/s3-bucket-insecure-plan.json "data.terraform.s3.security.violations"
```

### Test DynamoDB Policy
```bash
# Test secure DynamoDB configuration
opa eval -f pretty -d policy/dynamodb_security.rego -i test-plans/dynamodb/secure/dynamodb-table-secure-plan.json "data.terraform.dynamodb.security.allow"

# Test insecure DynamoDB configuration
opa eval -f policy/dynamodb_security.rego -i test-plans/dynamodb/insecure/dynamodb-table-insecure-plan.json "data.terraform.dynamodb.security.violations"
```

### Test RDS Policy
```bash
# Test secure RDS configuration
opa eval -f pretty -d policy/rds_security.rego -i test-plans/rds/secure/rds-instance-secure-plan.json "data.terraform.rds.security.allow"

# Test insecure RDS configuration
opa eval -f pretty -d policy/rds_security.rego -i test-plans/rds/insecure/rds-instance-insecure-plan.json "data.terraform.rds.security.violations"
```

### Test KMS Policy
```bash
# Test secure KMS configuration
opa eval -f pretty -d policy/kms_security.rego -i test-plans/kms/secure/kms-key-secure-plan.json "data.terraform.kms.security.allow"

# Test insecure KMS configuration
opa eval -f pretty -d policy/kms_security.rego -i test-plans/kms/insecure/kms-key-insecure-plan.json "data.terraform.kms.security.violations"
```

## Expected Results

### Secure Configurations
- **Allow**: `true`
- **Violations**: `{}` (empty)
- **Violation Count**: `0`

### Insecure Configurations
- **Allow**: `false`
- **Violations**: Contains specific security violations
- **Violation Count**: Number of violations detected

## Security Checks Covered

### S3 Bucket (10 checks)
- Encryption with aws:kms
- Bucket Keys enabled
- Public access blocks
- Ownership controls
- Versioning enabled
- Server access logging
- Bucket policy security statements

### DynamoDB Table (4 checks)
- Server-side encryption enabled
- Point-in-time recovery enabled
- Deletion protection enabled
- Backup enabled

### RDS Instance (9 checks)
- Storage encryption enabled
- Backup retention
- Deletion protection
- Final snapshot
- Auto minor version upgrade
- Performance Insights
- Enhanced monitoring
- Subnet group configuration
- Security group restrictions
- Secrets Manager integration

### KMS Key (6 checks)
- Key rotation enabled
- Deletion window (7-30 days)
- Policy configuration
- Root account access
- Principal restrictions
- Alias naming
- CloudWatch logging

## Notes

- These are mock Terraform plan files created for testing purposes
- They represent realistic AWS resource configurations
- Secure configurations follow AWS security best practices
- Insecure configurations intentionally violate security requirements
- Use these files to validate OPA policy behavior before applying to real Terraform plans
