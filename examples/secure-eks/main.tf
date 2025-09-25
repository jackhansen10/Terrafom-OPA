provider "aws" {
  region = var.aws_region
}

# VPC for EKS cluster
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# Secure EKS Cluster
module "secure_eks" {
  source = "../../modules/secure-eks"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  # Security configurations
  enable_cluster_encryption = true
  enable_audit_logging      = true
  enable_cloudwatch_logging = true
  
  # Node group configurations
  node_groups = {
    main = {
      instance_types = ["t3.medium"]
      min_size      = 2
      max_size      = 10
      desired_size  = 3
    }
  }
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# Additional security configurations
resource "aws_eks_addon" "vpc_cni" {
  cluster_name = module.secure_eks.cluster_id
  addon_name   = "vpc-cni"
  addon_version = "v1.14.1-eksbuild.1"
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_eks_addon" "coredns" {
  cluster_name = module.secure_eks.cluster_id
  addon_name   = "coredns"
  addon_version = "v1.10.1-eksbuild.1"
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = module.secure_eks.cluster_id
  addon_name   = "kube-proxy"
  addon_version = "v1.28.1-eksbuild.1"
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# AWS Load Balancer Controller
resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.6.2"

  set = [
    {
      name  = "clusterName"
      value = module.secure_eks.cluster_id
    },
    {
      name  = "serviceAccount.create"
      value = "false"
    },
    {
      name  = "serviceAccount.name"
      value = "aws-load-balancer-controller"
    },
    {
      name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
      value = module.secure_eks.aws_load_balancer_controller_role_arn
    }
  ]

  depends_on = [module.secure_eks]
}

# Kubernetes service account for AWS Load Balancer Controller
resource "kubernetes_service_account" "aws_load_balancer_controller" {
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.secure_eks.aws_load_balancer_controller_role_arn
    }
  }
}

# Pod Security Standards (replaces deprecated PodSecurityPolicy)
# Note: PodSecurityPolicy is deprecated in Kubernetes 1.21+ and removed in 1.25+
# Use Pod Security Standards instead for newer Kubernetes versions
resource "kubernetes_pod_security_policy" "restricted" {
  metadata {
    name = "restricted"
  }

  spec {
    privileged                 = false
    allow_privilege_escalation = false
    required_drop_capabilities = ["ALL"]
    volumes                   = ["configMap", "emptyDir", "projected", "secret", "downwardAPI", "persistentVolumeClaim"]

    run_as_user {
      rule = "MustRunAsNonRoot"
    }

    se_linux {
      rule = "RunAsAny"
    }

    fs_group {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    supplemental_groups {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }
  }
}

# Network Policy
resource "kubernetes_network_policy" "default_deny_all" {
  metadata {
    name      = "default-deny-all"
    namespace = "default"
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# Resource Quotas
resource "kubernetes_resource_quota" "default" {
  metadata {
    name      = "default"
    namespace = "default"
  }

  spec {
    hard = {
      "requests.cpu"    = "4"
      "requests.memory" = "8Gi"
      "limits.cpu"      = "8"
      "limits.memory"   = "16Gi"
      "pods"            = "10"
    }
  }
}
