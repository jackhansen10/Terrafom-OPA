package terraform.kms.security

# Helper: fetch planned KMS key resources
kms_keys := {r | some i
  input.resource_changes[i].type == "aws_kms_key"
  r := input.resource_changes[i]
}

kms_aliases := {r | some i
  input.resource_changes[i].type == "aws_kms_alias"
  r := input.resource_changes[i]
}

cloudwatch_log_groups := {r | some i
  input.resource_changes[i].type == "aws_cloudwatch_log_group"
  r := input.resource_changes[i]
}

# Violation messages
violations["KMS key rotation must be enabled for compliance"] if {
  some r in kms_keys
  after := r.change.after
  not after.enable_key_rotation
}

violations["KMS key deletion window must be between 7 and 30 days"] if {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  deletion_window < 7
}

violations["KMS key deletion window must be between 7 and 30 days"] if {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  deletion_window > 30
}

violations["KMS key must have a policy defined"] if {
  some r in kms_keys
  after := r.change.after
  not after.policy
}

violations["KMS key policy must contain at least one statement"] if {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  count(pd.Statement) == 0
}

violations["KMS key policy must grant access to root account"] if {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  count([s | s := pd.Statement[_]; s.Principal.AWS == "arn:aws:iam::123456789012:root"]) == 0
}

violations["KMS key policy should not grant kms:* to all principals"] if {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  some s in pd.Statement
  s.Effect == "Allow"
  s.Action == "kms:*"
  s.Principal.AWS == "*"
}

violations["KMS key must have an alias defined"] if {
  count(kms_aliases) == 0
}

violations["KMS alias must start with 'alias/'"] if {
  some r in kms_aliases
  after := r.change.after
  not startswith(after.name, "alias/")
}

violations["CloudWatch log group should be created for KMS audit logging"] if {
  count(cloudwatch_log_groups) == 0
}

violations["CloudWatch log group retention should be between 30 days and 7 years"] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  retention := after.retention_in_days
  retention < 30
}

violations["CloudWatch log group retention should be between 30 days and 7 years"] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  retention := after.retention_in_days
  retention > 2557
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