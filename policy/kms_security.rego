package terraform.kms.security

default allow = true

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

# DENY rules

# Key rotation must be enabled
deny[msg] {
  some r in kms_keys
  after := r.change.after
  not after.enable_key_rotation
  msg := "KMS key rotation must be enabled for compliance"
}

# Deletion window must be between 7-30 days
deny[msg] {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  not (deletion_window >= 7 and deletion_window <= 30)
  msg := "KMS key deletion window must be between 7 and 30 days"
}

# Key policy must exist and not be empty
deny[msg] {
  some r in kms_keys
  after := r.change.after
  not after.policy
  msg := "KMS key must have a policy defined"
}

deny[msg] {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  count(pd.Statement) == 0
  msg := "KMS key policy must contain at least one statement"
}

# Key policy must have root account access
deny[msg] {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  not some s in pd.Statement; s.Principal.AWS == "arn:aws:iam::*:root"
  msg := "KMS key policy must grant access to root account"
}

# Key policy should not grant overly broad permissions
deny[msg] {
  some r in kms_keys
  after := r.change.after
  policy := after.policy
  pd := json.unmarshal(policy)
  some s in pd.Statement
  s.Effect == "Allow"
  s.Action == "kms:*"
  s.Principal.AWS == "*"
  msg := "KMS key policy should not grant kms:* to all principals"
}

# KMS alias must be provided
deny[msg] {
  count(kms_aliases) == 0
  msg := "KMS key must have an alias defined"
}

# KMS alias must start with 'alias/'
deny[msg] {
  some r in kms_aliases
  after := r.change.after
  not startswith(after.name, "alias/")
  msg := "KMS alias must start with 'alias/'"
}

# CloudWatch logging should be enabled for audit
deny[msg] {
  count(cloudwatch_log_groups) == 0
  msg := "CloudWatch log group should be created for KMS audit logging"
}

# CloudWatch log group should have appropriate retention
deny[msg] {
  some r in cloudwatch_log_groups
  after := r.change.after
  retention := after.retention_in_days
  not (retention >= 30 && retention <= 2557) # 30 days to 7 years
  msg := "CloudWatch log group retention should be between 30 days and 7 years"
}

# Expose denies and an allow decision
violations := [m | m := deny[_]]

allow {
  count(violations) == 0
}
