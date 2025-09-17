package terraform.rds.security

default allow = true

# Helper: fetch planned RDS instance resources
rds_instances := {r | some i
  input.resource_changes[i].type == "aws_db_instance"
  r := input.resource_changes[i]
}

db_subnet_groups := {r | some i
  input.resource_changes[i].type == "aws_db_subnet_group"
  r := input.resource_changes[i]
}

security_groups := {r | some i
  input.resource_changes[i].type == "aws_security_group"
  r := input.resource_changes[i]
}

# DENY rules

# Encryption at rest must be enabled
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  not after.storage_encrypted
  msg := "RDS instance must have storage encryption enabled"
}

# Backup retention must be reasonable (at least 1 day for production)
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  retention := after.backup_retention_period
  retention < 1
  msg := "RDS instance backup retention should be at least 1 day"
}

# Deletion protection should be enabled for production
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  not after.deletion_protection
  msg := "RDS instance should have deletion protection enabled"
}

# Final snapshot should not be skipped
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  after.skip_final_snapshot
  msg := "RDS instance should not skip final snapshot"
}

# Auto minor version upgrade should be enabled
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  not after.auto_minor_version_upgrade
  msg := "RDS instance should have auto minor version upgrade enabled"
}

# Performance Insights should be enabled
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  not after.performance_insights_enabled
  msg := "RDS instance should have Performance Insights enabled"
}

# Enhanced monitoring should be enabled (monitoring_interval > 0)
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  monitoring := after.monitoring_interval
  monitoring == 0
  msg := "RDS instance should have enhanced monitoring enabled"
}

# DB instance must have a subnet group
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  not after.db_subnet_group_name
  msg := "RDS instance must have a DB subnet group"
}

# DB subnet group must exist
deny[msg] if {
  count(db_subnet_groups) == 0
  some r in rds_instances
  after := r.change.after
  after.db_subnet_group_name
  msg := "RDS instance references a DB subnet group that is not being created"
}

# Security group must exist
deny[msg] if {
  count(security_groups) == 0
  some r in rds_instances
  after := r.change.after
  count(after.vpc_security_group_ids) > 0
  msg := "RDS instance references security groups that are not being created"
}

# Security group should restrict access (not open to 0.0.0.0/0)
deny[msg] if {
  some r in security_groups
  after := r.change.after
  some ingress in after.ingress
  ingress.cidr_blocks[_] == "0.0.0.0/0"
  msg := "RDS security group should not allow access from 0.0.0.0/0"
}

# Master user password should be managed by Secrets Manager
deny[msg] if {
  some r in rds_instances
  after := r.change.after
  not after.manage_master_user_password
  msg := "RDS instance should use Secrets Manager for password management"
}

# Expose denies and an allow decision
violations := [m | m := deny[_]]

allow if {
  count(violations) == 0
}