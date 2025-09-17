variable "identifier" {
  description = "RDS instance identifier"
  type        = string
  default     = "secure-example-db"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "dev"
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN for encryption"
  type        = string
  default     = null
}

variable "vpc_id" {
  description = "VPC ID for the security group"
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Subnet IDs for the DB subnet group"
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the database"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

module "secure_rds" {
  source = "../../modules/secure-rds"

  identifier = var.identifier
  engine     = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  max_allocated_storage = 100
  storage_type = "gp2"
  storage_encrypted = true
  
  db_name = "example_db"
  username = "admin"
  manage_master_user_password = true
  
  kms_key_id = var.kms_key_arn
  
  backup_retention_period = 7
  backup_window = "03:00-04:00"
  maintenance_window = "sun:04:00-sun:05:00"
  
  auto_minor_version_upgrade = true
  deletion_protection = true
  skip_final_snapshot = false
  copy_tags_to_snapshot = true
  
  monitoring_interval = 60
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  performance_insights_enabled = true
  performance_insights_retention_period = 7
  
  subnet_ids = var.subnet_ids
  vpc_id = var.vpc_id
  allowed_cidr_blocks = var.allowed_cidr_blocks
  
  tags = {
    Environment = var.environment
    Owner       = "security"
    Purpose     = "example-database"
  }
}

output "db_instance_id" {
  description = "RDS instance ID"
  value       = module.secure_rds.db_instance_id
}

output "db_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = module.secure_rds.db_instance_endpoint
}

output "db_instance_port" {
  description = "Database port"
  value       = module.secure_rds.db_instance_port
}

output "db_instance_name" {
  description = "Database name"
  value       = module.secure_rds.db_instance_name
}

output "master_user_secret_arn" {
  description = "Master user secret ARN"
  value       = module.secure_rds.db_instance_master_user_secret_arn
}
