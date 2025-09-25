terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC for EKS cluster
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = false
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# Insecure EKS Cluster - violates multiple security best practices
resource "aws_eks_cluster" "insecure" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = "1.20"  # Old version

  vpc_config {
    subnet_ids              = module.vpc.public_subnet_ids  # Using public subnets
    endpoint_private_access = false  # Public endpoint access
    endpoint_public_access  = true   # Public endpoint access
    public_access_cidrs     = ["0.0.0.0/0"]  # Allow from anywhere
    # No security group specified
  }

  # No encryption at rest
  # No logging enabled

  depends_on = [
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
  ]

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
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

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

# Insecure Node Group
resource "aws_eks_node_group" "insecure" {
  cluster_name    = aws_eks_cluster.insecure.name
  node_group_name = "insecure-nodes"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = module.vpc.public_subnet_ids  # Using public subnets

  instance_types = ["t3.large"]
  capacity_type  = "SPOT"  # Using spot instances

  scaling_config {
    desired_size = 1  # Too few nodes
    max_size     = 200  # Too many nodes
    min_size     = 1    # Too few nodes
  }

  # No update configuration

  depends_on = [
    aws_iam_role_policy_attachment.nodes_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.nodes_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.nodes_AmazonEC2ContainerRegistryReadOnly,
  ]

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
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

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
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

# Insecure Security Group - allows all traffic
resource "aws_security_group" "insecure" {
  name_prefix = "${var.cluster_name}-insecure-"
  vpc_id      = module.vpc.vpc_id
  description = "Insecure security group for EKS cluster"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}
