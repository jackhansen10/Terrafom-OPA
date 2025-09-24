package terraform.s3.security

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

# Violation messages
violations["S3 bucket must use SSE with aws:kms"] if {
  some r in kms_configs
  after := r.change.after
  not after.rule[0].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

violations["S3 bucket should enable Bucket Keys for SSE-KMS"] if {
  some r in kms_configs
  after := r.change.after
  not after.rule[0].bucket_key_enabled
}

violations["S3 public access block: block_public_acls must be true"] if {
  some r in public_access_blocks
  after := r.change.after
  not after.block_public_acls
}

violations["S3 public access block: block_public_policy must be true"] if {
  some r in public_access_blocks
  after := r.change.after
  not after.block_public_policy
}

violations["S3 public access block: ignore_public_acls must be true"] if {
  some r in public_access_blocks
  after := r.change.after
  not after.ignore_public_acls
}

violations["S3 public access block: restrict_public_buckets must be true"] if {
  some r in public_access_blocks
  after := r.change.after
  not after.restrict_public_buckets
}

violations["S3 bucket ownership must be BucketOwnerEnforced"] if {
  some r in ownership_controls
  after := r.change.after
  not after.rule[0].object_ownership == "BucketOwnerEnforced"
}

violations["S3 bucket versioning must be Enabled"] if {
  some r in versioning_configs
  after := r.change.after
  not after.versioning_configuration.status == "Enabled"
}

violations["S3 server access logging must target a logging bucket"] if {
  some r in logging_configs
  after := r.change.after
  not after.target_bucket
}

violations["Bucket policy must deny insecure transport (TLS only)"] if {
  some r in bucket_policies
  policy_json := r.change.after.policy
  count([s | s := policy_json.Statement[_]; s.Sid == "DenyInsecureTransport"]) == 0
}

violations["Bucket policy must deny unencrypted uploads (aws:kms with CMK)"] if {
  some r in bucket_policies
  policy_json := r.change.after.policy
  count([s | s := policy_json.Statement[_]; s.Sid == "DenyUnEncryptedObjectUploads"]) == 0
}

violations["Bucket policy VPCE restriction present but not enforcing aws:sourceVpce"] if {
  some r in bucket_policies
  policy_json := r.change.after.policy
  some s in policy_json.Statement
  s.Sid == "DenyRequestsNotFromAllowedVPCEndpoints"
  not s.Condition.ForAnyValue.StringNotEquals["aws:sourceVpce"]
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