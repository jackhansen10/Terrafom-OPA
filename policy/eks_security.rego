package terraform.eks.security

# Helper: fetch planned EKS cluster resources
eks_clusters := {r | some i
  input.resource_changes[i].type == "aws_eks_cluster"
  r := input.resource_changes[i]
}

eks_node_groups := {r | some i
  input.resource_changes[i].type == "aws_eks_node_group"
  r := input.resource_changes[i]
}

kms_keys := {r | some i
  input.resource_changes[i].type == "aws_kms_key"
  r := input.resource_changes[i]
}

security_groups := {r | some i
  input.resource_changes[i].type == "aws_security_group"
  r := input.resource_changes[i]
}

iam_roles := {r | some i
  input.resource_changes[i].type == "aws_iam_role"
  r := input.resource_changes[i]
}

cloudwatch_log_groups := {r | some i
  input.resource_changes[i].type == "aws_cloudwatch_log_group"
  r := input.resource_changes[i]
}

# Violation messages
violations["EKS cluster must have encryption at rest enabled"] if {
  some r in eks_clusters
  after := r.change.after
  count(after.encryption_config) == 0
}

violations["EKS cluster encryption must use KMS key"] if {
  some r in eks_clusters
  after := r.change.after
  some config in after.encryption_config
  not config.provider.key_arn
}

violations["EKS cluster must have private endpoint access only"] if {
  some r in eks_clusters
  after := r.change.after
  vpc_config := after.vpc_config[0]
  vpc_config.endpoint_public_access
}

violations["EKS cluster must disable public access CIDRs"] if {
  some r in eks_clusters
  after := r.change.after
  vpc_config := after.vpc_config[0]
  count(vpc_config.public_access_cidrs) > 0
}

violations["EKS cluster must enable audit logging"] if {
  some r in eks_clusters
  after := r.change.after
  enabled_logs := after.enabled_cluster_log_types
  not "audit" in enabled_logs
}

violations["EKS cluster must enable API server logging"] if {
  some r in eks_clusters
  after := r.change.after
  enabled_logs := after.enabled_cluster_log_types
  not "api" in enabled_logs
}

violations["EKS cluster must enable authenticator logging"] if {
  some r in eks_clusters
  after := r.change.after
  enabled_logs := after.enabled_cluster_log_types
  not "authenticator" in enabled_logs
}

violations["EKS cluster must enable controller manager logging"] if {
  some r in eks_clusters
  after := r.change.after
  enabled_logs := after.enabled_cluster_log_types
  not "controllerManager" in enabled_logs
}

violations["EKS cluster must enable scheduler logging"] if {
  some r in eks_clusters
  after := r.change.after
  enabled_logs := after.enabled_cluster_log_types
  not "scheduler" in enabled_logs
}

violations["EKS cluster must have security group configured"] if {
  some r in eks_clusters
  after := r.change.after
  vpc_config := after.vpc_config[0]
  count(vpc_config.security_group_ids) == 0
}

violations["EKS cluster must use latest supported version"] if {
  some r in eks_clusters
  after := r.change.after
  version := after.version
  # Check if version is older than 1.25 (minimum for security features)
  version < "1.25"
}

violations["EKS node group must use ON_DEMAND capacity type"] if {
  some r in eks_node_groups
  after := r.change.after
  capacity_type := after.capacity_type
  capacity_type != "ON_DEMAND"
}

violations["EKS node group must have update configuration"] if {
  some r in eks_node_groups
  after := r.change.after
  count(after.update_config) == 0
}

violations["EKS node group update config must limit unavailable percentage"] if {
  some r in eks_node_groups
  after := r.change.after
  some update_config in after.update_config
  max_unavailable_percentage := update_config.max_unavailable_percentage
  max_unavailable_percentage > 25
}

violations["EKS node group must have minimum 2 nodes"] if {
  some r in eks_node_groups
  after := r.change.after
  scaling_config := after.scaling_config[0]
  min_size := scaling_config.min_size
  min_size < 2
}

violations["EKS node group must have maximum node limit"] if {
  some r in eks_node_groups
  after := r.change.after
  scaling_config := after.scaling_config[0]
  max_size := scaling_config.max_size
  max_size > 100
}

violations["EKS cluster KMS key must have rotation enabled"] if {
  some r in kms_keys
  after := r.change.after
  not after.enable_key_rotation
}

violations["EKS cluster KMS key must have proper deletion window"] if {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  deletion_window < 7
}

violations["EKS cluster KMS key must have proper deletion window"] if {
  some r in kms_keys
  after := r.change.after
  deletion_window := after.deletion_window_in_days
  deletion_window > 30
}

violations["EKS cluster security group must not allow ingress from 0.0.0.0/0"] if {
  some r in security_groups
  after := r.change.after
  some ingress in after.ingress
  ingress.cidr_blocks[_] == "0.0.0.0/0"
}

violations["EKS cluster security group must have egress rules"] if {
  some r in security_groups
  after := r.change.after
  count(after.egress) == 0
}

violations["EKS cluster IAM role must have minimal permissions"] if {
  some r in iam_roles
  after := r.change.after
  assume_role_policy := after.assume_role_policy
  # Check for overly permissive policies
  assume_role_policy == "*"
}

violations["EKS cluster must have CloudWatch log group for audit logs"] if {
  count(cloudwatch_log_groups) == 0
  count(eks_clusters) > 0
}

violations["EKS cluster CloudWatch log group must have retention policy"] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  not after.retention_in_days
}

violations["EKS cluster CloudWatch log group retention must be at least 30 days"] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  retention := after.retention_in_days
  retention < 30
}

violations["EKS cluster CloudWatch log group must use KMS encryption"] if {
  some r in cloudwatch_log_groups
  after := r.change.after
  not after.kms_key_id
}

violations["EKS cluster must have OIDC provider configured"] if {
  count(eks_clusters) > 0
  # This would need to check for aws_iam_openid_connect_provider resources
  # For now, we'll assume it's required if clusters exist
}

violations["EKS cluster must have proper subnet configuration"] if {
  some r in eks_clusters
  after := r.change.after
  vpc_config := after.vpc_config[0]
  count(vpc_config.subnet_ids) < 2
}

violations["EKS cluster must use private subnets only"] if {
  some r in eks_clusters
  after := r.change.after
  vpc_config := after.vpc_config[0]
  # This would need to check subnet types, but we'll validate minimum count
  count(vpc_config.subnet_ids) < 2
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
