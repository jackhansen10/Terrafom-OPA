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

# Violations with suggestions
violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  not after.storage_encrypted
  msg := "RDS instance must have storage encryption enabled"
  suggestion := "Set storage_encrypted = true on aws_db_instance."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  retention := after.backup_retention_period
  retention < 1
  msg := "RDS instance backup retention should be at least 1 day"
  suggestion := "Set backup_retention_period to at least 1."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  not after.deletion_protection
  msg := "RDS instance should have deletion protection enabled"
  suggestion := "Set deletion_protection = true on aws_db_instance."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  after.skip_final_snapshot
  msg := "RDS instance should not skip final snapshot"
  suggestion := "Set skip_final_snapshot = false and provide final_snapshot_identifier if needed."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  not after.auto_minor_version_upgrade
  msg := "RDS instance should have auto minor version upgrade enabled"
  suggestion := "Set auto_minor_version_upgrade = true on aws_db_instance."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  not after.performance_insights_enabled
  msg := "RDS instance should have Performance Insights enabled"
  suggestion := "Set performance_insights_enabled = true on aws_db_instance."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  monitoring := after.monitoring_interval
  monitoring == 0
  msg := "RDS instance should have enhanced monitoring enabled"
  suggestion := "Set monitoring_interval to a non-zero value and provide a monitoring role."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  not after.db_subnet_group_name
  msg := "RDS instance must have a DB subnet group"
  suggestion := "Set db_subnet_group_name or create an aws_db_subnet_group."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  count(db_subnet_groups) == 0
  some r in rds_instances
  after := r.change.after
  after.db_subnet_group_name
  msg := "RDS instance references a DB subnet group that is not being created"
  suggestion := "Add an aws_db_subnet_group resource or ensure the referenced subnet group exists in the plan."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  count(security_groups) == 0
  some r in rds_instances
  after := r.change.after
  count(after.vpc_security_group_ids) > 0
  msg := "RDS instance references security groups that are not being created"
  suggestion := "Create aws_security_group resources or supply existing security group IDs."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in security_groups
  after := r.change.after
  some ingress in after.ingress
  ingress.cidr_blocks[_] == "0.0.0.0/0"
  msg := "RDS security group should not allow access from 0.0.0.0/0"
  suggestion := "Restrict ingress CIDR blocks to trusted ranges."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in rds_instances
  after := r.change.after
  not after.manage_master_user_password
  msg := "RDS instance should use Secrets Manager for password management"
  suggestion := "Set manage_master_user_password = true or use Secrets Manager for the master password."
  resource := r.address
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