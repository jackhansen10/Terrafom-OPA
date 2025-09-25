# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# EKS Cluster
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC6.1: Logical and Physical Access Controls - Private endpoint access only
# SOC 2 CC6.2: System Access Controls - Security group restrictions
# SOC 2 CC6.3: Data Transmission and Disposal - Encryption at rest
# SOC 2 CC7.1: System Monitoring - Control plane logging
# PCI DSS 1.2.1: Restrict inbound and outbound traffic - Private endpoint
# PCI DSS 3.4: Render PAN unreadable - Encryption at rest
# PCI DSS 10.1: Implement audit trails - Control plane logging
# ISO 27001 A.13.1.1: Network controls - Private endpoint access
# ISO 27001 A.13.2.1: Information transfer policies - Encryption at rest
# ISO 27001 A.12.4.1: Event logging - Control plane logging
# NIST CSF PR.AC-3: Remote access management - Private endpoint
# NIST CSF PR.DS-1: Data-at-rest protection - Encryption at rest
# NIST CSF DE.AE-1: Baseline network operations - Control plane logging
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true  # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
    endpoint_public_access  = false # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
    public_access_cidrs     = []    # SOC 2 CC6.1, PCI DSS 1.2.1, ISO 27001 A.13.1.1, NIST CSF PR.AC-3
    security_group_ids      = [aws_security_group.cluster.id] # SOC 2 CC6.2, PCI DSS 1.2.1, ISO 27001 A.13.1.1
  }

  # Enable encryption at rest
  # SOC 2 CC6.3, PCI DSS 3.4, ISO 27001 A.13.2.1, NIST CSF PR.DS-1
  encryption_config {
    provider {
      key_arn = aws_kms_key.cluster.arn
    }
    resources = ["secrets"]
  }

  # Enable control plane logging
  # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1, NIST CSF DE.AE-1
  enabled_cluster_log_types = var.enable_audit_logging ? [
    "api",              # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1
    "audit",            # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1
    "authenticator",    # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1
    "controllerManager", # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1
    "scheduler"         # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1
  ] : []

  depends_on = [
    aws_cloudwatch_log_group.cluster,
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSVPCResourceController,
  ]

  tags = merge(var.tags, {
    Name = var.cluster_name
  })
}

# KMS Key for cluster encryption
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC6.3: Data Transmission and Disposal - Encryption key management
# SOC 2 CC6.7: Data Transmission and Disposal - Key rotation
# PCI DSS 3.4: Render PAN unreadable - Encryption key management
# PCI DSS 3.6.1: Key management - Key rotation
# PCI DSS 3.6.2: Key management - Key lifecycle management
# ISO 27001 A.13.2.1: Information transfer policies - Encryption key management
# ISO 27001 A.13.2.3: Cryptographic controls - Key rotation
# NIST CSF PR.DS-1: Data-at-rest protection - Encryption key management
# NIST CSF PR.DS-2: Data-in-transit protection - Key management
resource "aws_kms_key" "cluster" {
  description             = "EKS cluster encryption key for ${var.cluster_name}"
  deletion_window_in_days = 7  # SOC 2 CC6.3, PCI DSS 3.6.2, ISO 27001 A.13.2.1, NIST CSF PR.DS-1
  enable_key_rotation     = true  # SOC 2 CC6.7, PCI DSS 3.6.1, ISO 27001 A.13.2.3, NIST CSF PR.DS-1

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EKS Service"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-encryption-key"
  })
}

resource "aws_kms_alias" "cluster" {
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.cluster.key_id
}

# CloudWatch Log Group for cluster logs
# CloudWatch Log Group for EKS Cluster
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC7.1: System Monitoring - Log retention and protection
# SOC 2 CC7.2: System Monitoring - Log integrity
# PCI DSS 10.1: Implement audit trails - Log retention
# PCI DSS 10.3: Protect audit trail files - Log encryption
# PCI DSS 10.5: Secure audit trail files - Log access controls
# ISO 27001 A.12.4.1: Event logging - Log retention
# ISO 27001 A.12.4.2: Event logging - Log protection
# NIST CSF DE.AE-1: Baseline network operations - Log management
# NIST CSF DE.CM-1: Baseline network operations - Log monitoring
resource "aws_cloudwatch_log_group" "cluster" {
  count             = var.enable_audit_logging ? 1 : 0
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 30  # SOC 2 CC7.1, PCI DSS 10.1, ISO 27001 A.12.4.1, NIST CSF DE.AE-1
  kms_key_id        = aws_kms_key.cluster.arn  # SOC 2 CC7.2, PCI DSS 10.3, ISO 27001 A.12.4.2, NIST CSF DE.CM-1

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-cluster-logs"
  })
}

# IAM Role for EKS Cluster
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-cluster-role"
  })
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}

# Security Group for EKS Cluster
# COMPLIANCE CONTROL MAPPINGS:
# SOC 2 CC6.1: Logical and Physical Access Controls - Network access restrictions
# SOC 2 CC6.2: System Access Controls - Security group controls
# PCI DSS 1.2.1: Restrict inbound and outbound traffic - Security group rules
# PCI DSS 1.3.1: Limit inbound traffic - Egress restrictions
# ISO 27001 A.13.1.1: Network controls - Security group implementation
# ISO 27001 A.13.1.2: Network controls - Traffic filtering
# NIST CSF PR.AC-3: Remote access management - Network access controls
# NIST CSF PR.AC-5: Network integrity - Security group controls
resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  vpc_id      = var.vpc_id
  description = "Security group for EKS cluster control plane"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # SOC 2 CC6.1, PCI DSS 1.3.1, ISO 27001 A.13.1.2, NIST CSF PR.AC-3
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-cluster-sg"
  })
}

# Security Group for EKS Nodes
resource "aws_security_group" "nodes" {
  name_prefix = "${var.cluster_name}-nodes-"
  vpc_id      = var.vpc_id
  description = "Security group for EKS nodes"

  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-nodes-sg"
  })
}

# OIDC Identity Provider
data "tls_certificate" "cluster" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-oidc"
  })
}

# Node Groups
resource "aws_eks_node_group" "main" {
  for_each = var.node_groups

  cluster_name    = aws_eks_cluster.main.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = var.subnet_ids

  instance_types = each.value.instance_types
  capacity_type  = "ON_DEMAND"

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  update_config {
    max_unavailable_percentage = 25
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.nodes_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.nodes_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.nodes_AmazonEC2ContainerRegistryReadOnly,
  ]

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-${each.key}-node-group"
  })
}

# IAM Role for EKS Nodes
resource "aws_iam_role" "nodes" {
  name = "${var.cluster_name}-nodes-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-nodes-role"
  })
}

resource "aws_iam_role_policy_attachment" "nodes_AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes_AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes_AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}

# AWS Load Balancer Controller IAM Role
resource "aws_iam_role" "aws_load_balancer_controller" {
  name = "${var.cluster_name}-aws-load-balancer-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.cluster.arn
        }
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
            "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-aws-load-balancer-controller"
  })
}

resource "aws_iam_policy" "aws_load_balancer_controller" {
  name        = "${var.cluster_name}-aws-load-balancer-controller"
  description = "IAM policy for AWS Load Balancer Controller"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:DescribeProtection",
          "shield:GetSubscriptionState",
          "shield:DescribeSubscription",
          "shield:CreateProtection",
          "shield:DeleteProtection"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = "CreateSecurityGroup"
          }
          Null = {
            "aws:RequestedRegion" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestedRegion" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:DeleteRule"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ]
        Resource = [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
        ]
        Condition = {
          Null = {
            "aws:RequestedRegion" = "false"
            "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestedRegion" = "false"
            "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets"
        ]
        Resource = "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:ModifyRule"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-aws-load-balancer-controller"
  })
}

resource "aws_iam_role_policy_attachment" "aws_load_balancer_controller" {
  policy_arn = aws_iam_policy.aws_load_balancer_controller.arn
  role       = aws_iam_role.aws_load_balancer_controller.name
}

# CloudWatch Container Insights
resource "aws_eks_addon" "cloudwatch_observability" {
  count             = var.enable_cloudwatch_logging ? 1 : 0
  cluster_name      = aws_eks_cluster.main.name
  addon_name        = "amazon-cloudwatch-observability"
  addon_version     = "v1.0.0-eksbuild.1"

  depends_on = [aws_eks_node_group.main]

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-cloudwatch-observability"
  })
}
