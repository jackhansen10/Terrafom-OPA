package terraform.dynamodb.security

# Helper: fetch planned DynamoDB table resources
dynamodb_tables := {r | some i
  input.resource_changes[i].type == "aws_dynamodb_table"
  r := input.resource_changes[i]
}

dynamodb_backups := {r | some i
  input.resource_changes[i].type == "aws_dynamodb_table_backup"
  r := input.resource_changes[i]
}

# Violations with suggestions
violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  not after.server_side_encryption
  msg := "DynamoDB table must have server-side encryption enabled"
  suggestion := "Configure server_side_encryption on aws_dynamodb_table."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  sse := after.server_side_encryption
  not sse.enabled
  msg := "DynamoDB table server-side encryption must be enabled"
  suggestion := "Set server_side_encryption.enabled = true on aws_dynamodb_table."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  pitr := after.point_in_time_recovery
  not pitr.enabled
  msg := "DynamoDB table must have point-in-time recovery enabled"
  suggestion := "Set point_in_time_recovery.enabled = true on aws_dynamodb_table."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  deletion_protection := after.deletion_protection
  not deletion_protection.enabled
  msg := "DynamoDB table should have deletion protection enabled"
  suggestion := "Set deletion_protection.enabled = true on aws_dynamodb_table."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  backup := after.backup
  not backup.enabled
  msg := "DynamoDB table should have backup enabled"
  suggestion := "Enable backups (backup.enabled = true) on aws_dynamodb_table."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_backups
  after := r.change.after
  retention := after.backup_retention_period
  retention < 1
  msg := "DynamoDB backup retention must be between 1 and 35 days"
  suggestion := "Set backup_retention_period between 1 and 35."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_backups
  after := r.change.after
  retention := after.backup_retention_period
  retention > 35
  msg := "DynamoDB backup retention must be between 1 and 35 days"
  suggestion := "Set backup_retention_period between 1 and 35."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  not after.hash_key
  msg := "DynamoDB table must have a hash key defined"
  suggestion := "Set hash_key on aws_dynamodb_table."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  hash_key := after.hash_key
  attributes := after.attribute
  count([attr | attr := attributes[_]; attr.name == hash_key]) == 0
  msg := "DynamoDB table must have attribute definition for hash key"
  suggestion := "Add an attribute definition matching the hash_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  range_key := after.range_key
  range_key != null
  attributes := after.attribute
  count([attr | attr := attributes[_]; attr.name == range_key]) == 0
  msg := "DynamoDB table must have attribute definition for range key"
  suggestion := "Add an attribute definition matching the range_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  gsis := after.global_secondary_index
  attributes := after.attribute
  some gsi in gsis
  count([attr | attr := attributes[_]; attr.name == gsi.hash_key]) == 0
  msg := "DynamoDB GSI hash key must have attribute definition"
  suggestion := "Add attribute definitions for each GSI hash_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  lsis := after.local_secondary_index
  attributes := after.attribute
  some lsi in lsis
  count([attr | attr := attributes[_]; attr.name == lsi.range_key]) == 0
  msg := "DynamoDB LSI range key must have attribute definition"
  suggestion := "Add attribute definitions for each LSI range_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in dynamodb_tables
  after := r.change.after
  ttl := after.ttl
  ttl.enabled
  not ttl.attribute_name
  msg := "DynamoDB TTL must specify attribute name when enabled"
  suggestion := "Set ttl.attribute_name to the attribute holding epoch timestamps."
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