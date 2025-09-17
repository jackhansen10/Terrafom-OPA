# RDS Instance
resource "aws_db_instance" "this" {
  identifier     = var.identifier
  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = var.storage_type
  storage_encrypted     = var.storage_encrypted
  kms_key_id           = var.kms_key_id

  db_name  = var.db_name
  username = var.username
  password = var.password

  manage_master_user_password = var.manage_master_user_password

  vpc_security_group_ids = var.vpc_security_group_ids
  db_subnet_group_name   = var.db_subnet_group_name
  parameter_group_name   = var.parameter_group_name

  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window

  auto_minor_version_upgrade = var.auto_minor_version_upgrade
  deletion_protection       = var.deletion_protection
  skip_final_snapshot      = var.skip_final_snapshot
  final_snapshot_identifier = var.final_snapshot_identifier != null ? var.final_snapshot_identifier : "${var.identifier}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  copy_tags_to_snapshot    = var.copy_tags_to_snapshot

  monitoring_interval = var.monitoring_interval
  monitoring_role_arn = var.monitoring_role_arn

  enabled_cloudwatch_logs_exports = var.enabled_cloudwatch_logs_exports

  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_retention_period
  performance_insights_kms_key_id      = var.performance_insights_kms_key_id

  tags = merge(var.tags, {
    Name    = var.identifier
    Purpose = "secure-database"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# DB Subnet Group (if not provided)
resource "aws_db_subnet_group" "this" {
  count = var.db_subnet_group_name == null ? 1 : 0

  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name    = "${var.identifier}-subnet-group"
    Purpose = "rds-subnet-group"
  })
}

# Security Group (if not provided)
resource "aws_security_group" "this" {
  count = length(var.vpc_security_group_ids) == 0 ? 1 : 0

  name_prefix = "${var.identifier}-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = var.engine == "postgres" ? 5432 : 3306
    to_port     = var.engine == "postgres" ? 5432 : 3306
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name    = "${var.identifier}-sg"
    Purpose = "rds-security-group"
  })
}

# Additional variables for subnet group and security group
variable "subnet_ids" {
  description = "List of subnet IDs for the DB subnet group."
  type        = list(string)
  default     = []
}

variable "vpc_id" {
  description = "VPC ID for the security group."
  type        = string
  default     = null
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access the RDS instance."
  type        = list(string)
  default     = ["10.0.0.0/8"]
}
