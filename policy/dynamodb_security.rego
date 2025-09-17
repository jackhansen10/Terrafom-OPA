package terraform.dynamodb.security

default allow = true

# Helper: fetch planned DynamoDB table resources
dynamodb_tables := {r | some i
  input.resource_changes[i].type == "aws_dynamodb_table"
  r := input.resource_changes[i]
}

dynamodb_backups := {r | some i
  input.resource_changes[i].type == "aws_dynamodb_table_backup"
  r := input.resource_changes[i]
}

# DENY rules

# Encryption at rest must be enabled
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  not after.server_side_encryption
  msg := "DynamoDB table must have server-side encryption enabled"
}

deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  sse := after.server_side_encryption
  not sse.enabled
  msg := "DynamoDB table server-side encryption must be enabled"
}

# Point-in-time recovery must be enabled
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  pitr := after.point_in_time_recovery
  not pitr.enabled
  msg := "DynamoDB table must have point-in-time recovery enabled"
}

# Deletion protection should be enabled for production
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  deletion_protection := after.deletion_protection
  not deletion_protection.enabled
  msg := "DynamoDB table should have deletion protection enabled"
}

# Backup should be enabled
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  backup := after.backup
  not backup.enabled
  msg := "DynamoDB table should have backup enabled"
}

# Backup retention should be reasonable (1-35 days)
deny[msg] {
  some r in dynamodb_backups
  after := r.change.after
  retention := after.backup_retention_period
  not (retention >= 1 and retention <= 35)
  msg := "DynamoDB backup retention must be between 1 and 35 days"
}

# Table must have a hash key defined
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  not after.hash_key
  msg := "DynamoDB table must have a hash key defined"
}

# Attributes must be defined for hash key
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  hash_key := after.hash_key
  attributes := after.attribute
  not some attr in attributes; attr.name == hash_key
  msg := "DynamoDB table must have attribute definition for hash key"
}

# If range key is defined, it must have an attribute definition
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  range_key := after.range_key
  range_key != null
  attributes := after.attribute
  not some attr in attributes; attr.name == range_key
  msg := "DynamoDB table must have attribute definition for range key"
}

# GSI hash keys must have attribute definitions
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  gsis := after.global_secondary_index
  attributes := after.attribute
  some gsi in gsis
  not some attr in attributes; attr.name == gsi.hash_key
  msg := "DynamoDB GSI hash key must have attribute definition"
}

# LSI range keys must have attribute definitions
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  lsis := after.local_secondary_index
  attributes := after.attribute
  some lsi in lsis
  not some attr in attributes; attr.name == lsi.range_key
  msg := "DynamoDB LSI range key must have attribute definition"
}

# TTL should be configured if enabled
deny[msg] {
  some r in dynamodb_tables
  after := r.change.after
  ttl := after.ttl
  ttl.enabled
  not ttl.attribute_name
  msg := "DynamoDB TTL must specify attribute name when enabled"
}

# Expose denies and an allow decision
violations := [m | m := deny[_]]

allow {
  count(violations) == 0
}
