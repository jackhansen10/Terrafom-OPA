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

# Violation messages
violations["DynamoDB table must have server-side encryption enabled"] if {
  some r in dynamodb_tables
  after := r.change.after
  not after.server_side_encryption
}

violations["DynamoDB table server-side encryption must be enabled"] if {
  some r in dynamodb_tables
  after := r.change.after
  sse := after.server_side_encryption
  not sse.enabled
}

violations["DynamoDB table must have point-in-time recovery enabled"] if {
  some r in dynamodb_tables
  after := r.change.after
  pitr := after.point_in_time_recovery
  not pitr.enabled
}

violations["DynamoDB table should have deletion protection enabled"] if {
  some r in dynamodb_tables
  after := r.change.after
  deletion_protection := after.deletion_protection
  not deletion_protection.enabled
}

violations["DynamoDB table should have backup enabled"] if {
  some r in dynamodb_tables
  after := r.change.after
  backup := after.backup
  not backup.enabled
}

violations["DynamoDB backup retention must be between 1 and 35 days"] if {
  some r in dynamodb_backups
  after := r.change.after
  retention := after.backup_retention_period
  retention < 1
}

violations["DynamoDB backup retention must be between 1 and 35 days"] if {
  some r in dynamodb_backups
  after := r.change.after
  retention := after.backup_retention_period
  retention > 35
}

violations["DynamoDB table must have a hash key defined"] if {
  some r in dynamodb_tables
  after := r.change.after
  not after.hash_key
}

violations["DynamoDB table must have attribute definition for hash key"] if {
  some r in dynamodb_tables
  after := r.change.after
  hash_key := after.hash_key
  attributes := after.attribute
  count([attr | attr := attributes[_]; attr.name == hash_key]) == 0
}

violations["DynamoDB table must have attribute definition for range key"] if {
  some r in dynamodb_tables
  after := r.change.after
  range_key := after.range_key
  range_key != null
  attributes := after.attribute
  count([attr | attr := attributes[_]; attr.name == range_key]) == 0
}

violations["DynamoDB GSI hash key must have attribute definition"] if {
  some r in dynamodb_tables
  after := r.change.after
  gsis := after.global_secondary_index
  attributes := after.attribute
  some gsi in gsis
  count([attr | attr := attributes[_]; attr.name == gsi.hash_key]) == 0
}

violations["DynamoDB LSI range key must have attribute definition"] if {
  some r in dynamodb_tables
  after := r.change.after
  lsis := after.local_secondary_index
  attributes := after.attribute
  some lsi in lsis
  count([attr | attr := attributes[_]; attr.name == lsi.range_key]) == 0
}

violations["DynamoDB TTL must specify attribute name when enabled"] if {
  some r in dynamodb_tables
  after := r.change.after
  ttl := after.ttl
  ttl.enabled
  not ttl.attribute_name
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