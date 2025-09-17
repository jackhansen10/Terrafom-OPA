output "db_instance_id" {
  description = "The RDS instance ID"
  value       = aws_db_instance.this.id
}

output "db_instance_arn" {
  description = "The ARN of the RDS instance"
  value       = aws_db_instance.this.arn
}

output "db_instance_endpoint" {
  description = "The RDS instance endpoint"
  value       = aws_db_instance.this.endpoint
}

output "db_instance_hosted_zone_id" {
  description = "The canonical hosted zone ID of the DB instance"
  value       = aws_db_instance.this.hosted_zone_id
}

output "db_instance_address" {
  description = "The hostname of the RDS instance"
  value       = aws_db_instance.this.address
}

output "db_instance_port" {
  description = "The database port"
  value       = aws_db_instance.this.port
}

output "db_instance_name" {
  description = "The database name"
  value       = aws_db_instance.this.db_name
}

output "db_instance_username" {
  description = "The master username for the database"
  value       = aws_db_instance.this.username
}

output "db_instance_password" {
  description = "The database password (this may not be available if managed by Secrets Manager)"
  value       = aws_db_instance.this.password
  sensitive   = true
}

output "db_instance_master_user_secret_arn" {
  description = "The ARN of the master user secret (Only available when manage_master_user_password is set to true)"
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "db_subnet_group_id" {
  description = "The db subnet group name"
  value       = var.db_subnet_group_name != null ? var.db_subnet_group_name : aws_db_subnet_group.this[0].id
}

output "db_subnet_group_arn" {
  description = "The ARN of the db subnet group"
  value       = var.db_subnet_group_name != null ? null : aws_db_subnet_group.this[0].arn
}

output "security_group_id" {
  description = "The ID of the security group"
  value       = length(var.vpc_security_group_ids) > 0 ? var.vpc_security_group_ids[0] : aws_security_group.this[0].id
}

output "security_group_arn" {
  description = "The ARN of the security group"
  value       = length(var.vpc_security_group_ids) > 0 ? null : aws_security_group.this[0].arn
}
