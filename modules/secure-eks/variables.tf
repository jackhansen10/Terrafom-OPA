variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.28"
}

variable "vpc_id" {
  description = "VPC ID where the cluster will be created"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the cluster"
  type        = list(string)
}

variable "enable_cluster_encryption" {
  description = "Enable EKS cluster encryption at rest"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable EKS control plane audit logging"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logging" {
  description = "Enable CloudWatch container insights"
  type        = bool
  default     = true
}

variable "node_groups" {
  description = "Map of node group configurations"
  type = map(object({
    instance_types = list(string)
    min_size      = number
    max_size      = number
    desired_size  = number
  }))
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

