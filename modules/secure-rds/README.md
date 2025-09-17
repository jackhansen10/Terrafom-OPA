# Secure RDS Module

Creates a secure AWS RDS instance with compliance features aligned with SOC 2, PCI DSS, ISO 27001, and NIST CSF requirements.

## Features

- Encryption at rest with KMS (customer-managed or AWS-managed keys)
- Automated backups with configurable retention
- Point-in-time recovery support
- Enhanced monitoring and Performance Insights
- CloudWatch logs export
- Deletion protection
- Final snapshot on deletion
- Auto minor version upgrades
- Secure networking with VPC and security groups
- Password management via AWS Secrets Manager

## Inputs

- `identifier` (string) – The name of the RDS instance
- `engine` (string) – Database engine; default 'mysql'
- `engine_version` (string|null) – Engine version; default null (latest)
- `instance_class` (string) – Instance type; default 'db.t3.micro'
- `allocated_storage` (number) – Allocated storage in GB; default 20
- `max_allocated_storage` (number|null) – Max auto-scaling storage; default null
- `storage_type` (string) – Storage type; default 'gp2'
- `storage_encrypted` (bool) – Enable encryption at rest; default true
- `kms_key_id` (string|null) – KMS key ARN; default null (AWS-managed)
- `db_name` (string|null) – Database name; default null
- `username` (string) – Master username; default 'admin'
- `password` (string|null) – Master password; default null (use Secrets Manager)
- `manage_master_user_password` (bool) – Use Secrets Manager; default true
- `vpc_security_group_ids` (list(string)) – Security groups; default []
- `db_subnet_group_name` (string|null) – Subnet group; default null (auto-create)
- `parameter_group_name` (string|null) – Parameter group; default null
- `backup_retention_period` (number) – Backup retention (0-35 days); default 7
- `backup_window` (string) – Backup window; default '03:00-04:00'
- `maintenance_window` (string) – Maintenance window; default 'sun:04:00-sun:05:00'
- `auto_minor_version_upgrade` (bool) – Auto minor upgrades; default true
- `deletion_protection` (bool) – Deletion protection; default true
- `skip_final_snapshot` (bool) – Skip final snapshot; default false
- `final_snapshot_identifier` (string|null) – Final snapshot name; default auto-generated
- `copy_tags_to_snapshot` (bool) – Copy tags to snapshot; default true
- `monitoring_interval` (number) – Enhanced monitoring interval; default 60
- `monitoring_role_arn` (string|null) – Monitoring role ARN; default null
- `enabled_cloudwatch_logs_exports` (list(string)) – CloudWatch logs; default []
- `performance_insights_enabled` (bool) – Performance Insights; default true
- `performance_insights_retention_period` (number) – PI retention; default 7
- `performance_insights_kms_key_id` (string|null) – PI KMS key; default null
- `subnet_ids` (list(string)) – Subnet IDs for auto-created subnet group; default []
- `vpc_id` (string|null) – VPC ID for auto-created security group; default null
- `allowed_cidr_blocks` (list(string)) – Allowed CIDR blocks; default ['10.0.0.0/8']
- `tags` (map(string)) – Tags to apply; default {}

## Outputs

- `db_instance_id`, `db_instance_arn`, `db_instance_endpoint`
- `db_instance_address`, `db_instance_port`, `db_instance_name`
- `db_instance_username`, `db_instance_password` (sensitive)
- `db_instance_master_user_secret_arn`
- `db_subnet_group_id`, `db_subnet_group_arn`
- `security_group_id`, `security_group_arn`

## Compliance Features

- **Encryption at Rest**: KMS encryption with customer-managed or AWS-managed keys
- **Backup & Recovery**: Automated backups and point-in-time recovery
- **Data Protection**: Deletion protection and final snapshots
- **Access Control**: VPC security groups and subnet isolation
- **Audit Logging**: CloudWatch logs and Performance Insights
- **Monitoring**: Enhanced monitoring and automated maintenance
- **Secrets Management**: Password management via AWS Secrets Manager

## Control Mapping

- **SOC 2 CC6.1/CC6.6**: Access controls and data protection
- **PCI DSS 3.x/4.x**: Encryption and secure data storage
- **ISO 27001 A.8/A.10/A.12**: Asset protection, cryptography, operations security
- **NIST CSF PR.DS**: Data security and protection

## Usage Example

```hcl
module "secure_rds" {
  source = "../../modules/secure-rds"

  identifier = "secure-database"
  engine     = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.small"
  
  allocated_storage = 100
  max_allocated_storage = 1000
  storage_type = "gp3"
  
  db_name = "secureapp"
  username = "admin"
  
  kms_key_id = module.secure_kms_key.key_arn
  
  backup_retention_period = 7
  deletion_protection = true
  
  performance_insights_enabled = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  subnet_ids = ["subnet-12345", "subnet-67890"]
  vpc_id = "vpc-12345"
  allowed_cidr_blocks = ["10.0.0.0/16"]
  
  tags = {
    Environment = "prod"
    Owner       = "security"
  }
}
```
