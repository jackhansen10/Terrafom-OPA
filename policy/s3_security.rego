package terraform.s3.security

default allow = true

# Helper: fetch planned S3 bucket resources
s3_buckets := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket"
  r := input.resource_changes[i]
}

kms_configs := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket_server_side_encryption_configuration"
  r := input.resource_changes[i]
}

public_access_blocks := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket_public_access_block"
  r := input.resource_changes[i]
}

ownership_controls := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket_ownership_controls"
  r := input.resource_changes[i]
}

versioning_configs := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket_versioning"
  r := input.resource_changes[i]
}

logging_configs := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket_logging"
  r := input.resource_changes[i]
}

bucket_policies := {r | some i
  input.resource_changes[i].type == "aws_s3_bucket_policy"
  r := input.resource_changes[i]
}

# DENY rules

# Encryption at rest must be enabled with aws:kms and bucket_key_enabled true
deny[msg] {
  some r in kms_configs
  after := r.change.after
  not after.rule[0].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
  msg := "S3 bucket must use SSE with aws:kms"
}

deny[msg] {
  some r in kms_configs
  after := r.change.after
  not after.rule[0].bucket_key_enabled
  msg := "S3 bucket should enable Bucket Keys for SSE-KMS"
}

# Public access block must be fully enforced
deny[msg] {
  some r in public_access_blocks
  after := r.change.after
  not after.block_public_acls
  msg := "S3 public access block: block_public_acls must be true"
}

deny[msg] {
  some r in public_access_blocks
  after := r.change.after
  not after.block_public_policy
  msg := "S3 public access block: block_public_policy must be true"
}

deny[msg] {
  some r in public_access_blocks
  after := r.change.after
  not after.ignore_public_acls
  msg := "S3 public access block: ignore_public_acls must be true"
}

deny[msg] {
  some r in public_access_blocks
  after := r.change.after
  not after.restrict_public_buckets
  msg := "S3 public access block: restrict_public_buckets must be true"
}

# Ownership must be BucketOwnerEnforced on primary bucket to disable ACLs
deny[msg] {
  some r in ownership_controls
  after := r.change.after
  not after.rule[0].object_ownership == "BucketOwnerEnforced"
  msg := "S3 bucket ownership must be BucketOwnerEnforced"
}

# Versioning must be enabled
deny[msg] {
  some r in versioning_configs
  after := r.change.after
  not after.versioning_configuration.status == "Enabled"
  msg := "S3 bucket versioning must be Enabled"
}

# Server access logging must be configured
deny[msg] {
  some r in logging_configs
  after := r.change.after
  not after.target_bucket
  msg := "S3 server access logging must target a logging bucket"
}

# Bucket policy must deny insecure transport and unencrypted uploads
deny[msg] {
  some r in bucket_policies
  json := r.change.after.policy
  pd := json.unmarshal(json)
  # Check if DenyInsecureTransport statement exists
  count([s | s := pd.Statement[_]; s.Sid == "DenyInsecureTransport"]) == 0
  msg := "Bucket policy must deny insecure transport (TLS only)"
}

deny[msg] {
  some r in bucket_policies
  json := r.change.after.policy
  pd := json.unmarshal(json)
  # Check if DenyUnEncryptedObjectUploads statement exists
  count([s | s := pd.Statement[_]; s.Sid == "DenyUnEncryptedObjectUploads"]) == 0
  msg := "Bucket policy must deny unencrypted uploads (aws:kms with CMK)"
}

# Optionally check for VPC endpoint restriction when provided via variable (detected by presence of statement Sid)
deny[msg] {
  some r in bucket_policies
  json := r.change.after.policy
  pd := json.unmarshal(json)
  # Check if VPCE restriction statement exists but doesn't enforce aws:sourceVpce
  some s in pd.Statement
  s.Sid == "DenyRequestsNotFromAllowedVPCEndpoints"
  not s.Condition.ForAnyValue.StringNotEquals["aws:sourceVpce"]
  msg := "Bucket policy VPCE restriction present but not enforcing aws:sourceVpce"
}

# Expose denies and an allow decision
violations := [m | m := deny[_]]

allow {
  count(violations) == 0
}
