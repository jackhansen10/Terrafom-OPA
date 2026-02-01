output "cluster_id" {
  description = "EKS cluster ID"
  value       = aws_eks_cluster.main.id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = aws_eks_cluster.main.arn
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID of the EKS cluster"
  value       = aws_security_group.cluster.id
}

output "node_groups" {
  description = "Map of node group information"
  value = {
    for k, v in aws_eks_node_group.main : k => {
      arn         = v.arn
      status      = v.status
      capacity_type = v.capacity_type
      instance_types = v.instance_types
      scaling_config = v.scaling_config
    }
  }
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA"
  value       = aws_iam_openid_connect_provider.cluster.arn
}

output "oidc_provider_url" {
  description = "OIDC provider URL for IRSA"
  value       = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

output "kms_key_arn" {
  description = "KMS key ARN used for cluster encryption"
  value       = aws_kms_key.cluster.arn
}

output "kms_key_id" {
  description = "KMS key ID used for cluster encryption"
  value       = aws_kms_key.cluster.key_id
}

output "aws_load_balancer_controller_role_arn" {
  description = "IAM role ARN for AWS Load Balancer Controller"
  value       = aws_iam_role.aws_load_balancer_controller.arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name for cluster logs"
  value       = var.enable_audit_logging ? aws_cloudwatch_log_group.cluster[0].name : null
}

