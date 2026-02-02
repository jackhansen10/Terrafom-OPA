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

# Violations with suggestions
violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  not after.enable_key_rotation
  msg := "KMS key rotation must be enabled for compliance"
  suggestion := "Set enable_key_rotation = true on aws_kms_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  deletion_window < 7
  msg := "KMS key deletion window must be between 7 and 30 days"
  suggestion := "Set deletion_window_in_days between 7 and 30 on aws_kms_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  deletion_window > 30
  msg := "KMS key deletion window must be between 7 and 30 days"
  suggestion := "Set deletion_window_in_days between 7 and 30 on aws_kms_key."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  not after.policy
  msg := "KMS key must have a policy defined"
  suggestion := "Provide a key policy JSON on aws_kms_key.policy or use a secure default."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  count(pd.Statement) == 0
  msg := "KMS key policy must contain at least one statement"
  suggestion := "Add at least one statement to the KMS key policy allowing required principals."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  count([s | s := pd.Statement[_]; s.Principal.AWS == "arn:aws:iam::123456789012:root"]) == 0
  msg := "KMS key policy must grant access to root account"
  suggestion := "Include a statement that grants kms:* to the account root principal."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  some s in pd.Statement
  s.Effect == "Allow"
  s.Action == "kms:*"
  s.Principal.AWS == "*"
  msg := "KMS key policy should not grant kms:* to all principals"
  suggestion := "Remove wildcard principals and scope access to specific IAM principals/services."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  count(kms_aliases) == 0
  msg := "KMS key must have an alias defined"
  suggestion := "Create an aws_kms_alias resource pointing to the key."
  resource := "aws_kms_alias"
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in kms_aliases
  after := r.change.after
  not startswith(after.name, "alias/")
  msg := "KMS alias must start with 'alias/'"
  suggestion := "Use an alias name that starts with \"alias/\"."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  count(cloudwatch_log_groups) == 0
  msg := "CloudWatch log group should be created for KMS audit logging"
  suggestion := "Create an aws_cloudwatch_log_group for KMS audit logs."
  resource := "aws_cloudwatch_log_group"
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  retention := after.retention_in_days
  retention < 30
  msg := "CloudWatch log group retention should be between 30 days and 7 years"
  suggestion := "Set retention_in_days between 30 and 2557."
  resource := r.address
}

violations[{"msg": msg, "suggestion": suggestion, "resource": resource}] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  retention := after.retention_in_days
  retention > 2557
  msg := "CloudWatch log group retention should be between 30 days and 7 years"
  suggestion := "Set retention_in_days between 30 and 2557."
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