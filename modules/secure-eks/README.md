# Secure EKS Cluster Module

This module creates a secure EKS cluster with comprehensive security configurations following AWS best practices.

## Features

- **Encryption**: EKS cluster encryption at rest and in transit
- **Network Security**: Private subnets, security groups, and VPC endpoints
- **Access Control**: IAM roles, policies, and RBAC configurations
- **Monitoring**: CloudWatch logging, monitoring, and audit logging
- **Compliance**: CIS benchmarks and security hardening
- **Secrets Management**: Integration with AWS Secrets Manager
- **Pod Security**: Pod Security Standards and Network Policies

## Usage

```hcl
module "secure_eks" {
  source = "./modules/secure-eks"

  cluster_name    = "secure-cluster"
  cluster_version = "1.28"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnet_ids
  
  # Security configurations
  enable_cluster_encryption = true
  enable_audit_logging      = true
  enable_cloudwatch_logging = true
  
  # Node group configurations
  node_groups = {
    main = {
      instance_types = ["t3.medium"]
      min_size      = 1
      max_size      = 10
      desired_size  = 3
    }
  }
  
  tags = {
    Environment = "production"
    Project     = "secure-kubernetes"
  }
}
```

## Security Features

### Cluster Security
- EKS cluster encryption at rest using AWS KMS
- Private cluster endpoint with restricted access
- Control plane logging enabled (audit, api, authenticator, controllerManager, scheduler)
- Cluster version with latest security patches

### Network Security
- Private subnets for worker nodes
- Security groups with least privilege access
- VPC endpoints for AWS services
- Network policies for pod-to-pod communication

### Access Control
- IAM roles with minimal required permissions
- RBAC configurations
- Pod Security Standards enforcement
- Service account token management

### Monitoring & Compliance
- CloudWatch container insights
- AWS Config rules for EKS compliance
- Security scanning and vulnerability assessment
- Audit trail and logging

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | >= 5.0 |
| kubernetes | >= 2.20 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 5.0 |
| kubernetes | >= 2.20 |
| helm | >= 2.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| cluster_name | Name of the EKS cluster | `string` | n/a | yes |
| cluster_version | Kubernetes version for the EKS cluster | `string` | `"1.28"` | no |
| vpc_id | VPC ID where the cluster will be created | `string` | n/a | yes |
| subnet_ids | List of subnet IDs for the cluster | `list(string)` | n/a | yes |
| enable_cluster_encryption | Enable EKS cluster encryption at rest | `bool` | `true` | no |
| enable_audit_logging | Enable EKS control plane audit logging | `bool` | `true` | no |
| enable_cloudwatch_logging | Enable CloudWatch container insights | `bool` | `true` | no |
| node_groups | Map of node group configurations | `map(object)` | n/a | yes |
| tags | Tags to apply to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| cluster_id | EKS cluster ID |
| cluster_arn | EKS cluster ARN |
| cluster_endpoint | EKS cluster endpoint |
| cluster_security_group_id | Security group ID of the EKS cluster |
| node_groups | Map of node group information |
| oidc_provider_arn | OIDC provider ARN for IRSA |
| oidc_provider_url | OIDC provider URL for IRSA |
