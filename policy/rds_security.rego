package terraform.rds.security

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

# Violation messages
violations["RDS instance must have storage encryption enabled"] if {
  some r in rds_instances
  after := r.change.after
  not after.storage_encrypted
}

violations["RDS instance backup retention should be at least 1 day"] if {
  some r in rds_instances
  after := r.change.after
  retention := after.backup_retention_period
  retention < 1
}

violations["RDS instance should have deletion protection enabled"] if {
  some r in rds_instances
  after := r.change.after
  not after.deletion_protection
}

violations["RDS instance should not skip final snapshot"] if {
  some r in rds_instances
  after := r.change.after
  after.skip_final_snapshot
}

violations["RDS instance should have auto minor version upgrade enabled"] if {
  some r in rds_instances
  after := r.change.after
  not after.auto_minor_version_upgrade
}

violations["RDS instance should have Performance Insights enabled"] if {
  some r in rds_instances
  after := r.change.after
  not after.performance_insights_enabled
}

violations["RDS instance should have enhanced monitoring enabled"] if {
  some r in rds_instances
  after := r.change.after
  monitoring := after.monitoring_interval
  monitoring == 0
}

violations["RDS instance must have a DB subnet group"] if {
  some r in rds_instances
  after := r.change.after
  not after.db_subnet_group_name
}

violations["RDS instance references a DB subnet group that is not being created"] if {
  count(db_subnet_groups) == 0
  some r in rds_instances
  after := r.change.after
  after.db_subnet_group_name
}

violations["RDS instance references security groups that are not being created"] if {
  count(security_groups) == 0
  some r in rds_instances
  after := r.change.after
  count(after.vpc_security_group_ids) > 0
}

violations["RDS security group should not allow access from 0.0.0.0/0"] if {
  some r in security_groups
  after := r.change.after
  some ingress in after.ingress
  ingress.cidr_blocks[_] == "0.0.0.0/0"
}

violations["RDS instance should use Secrets Manager for password management"] if {
  some r in rds_instances
  after := r.change.after
  not after.manage_master_user_password
}

# Allow decision
allow if {
  violation_count == 0
}

allow := false if {
  violation_count > 0
}

# Helper to get violation count
violation_count := count(violations)