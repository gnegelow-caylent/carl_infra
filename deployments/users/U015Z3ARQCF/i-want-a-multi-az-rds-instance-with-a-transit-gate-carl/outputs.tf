```hcl
# outputs.tf - CARL Compliance Infrastructure Outputs

# VPC Outputs
output "vpc_id" {
  description = "VPC ID for the production environment"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

# Subnet Outputs
output "private_subnet_1a_id" {
  description = "Private subnet ID in AZ us-east-1a"
  value       = aws_subnet.private_1a.id
}

output "private_subnet_1b_id" {
  description = "Private subnet ID in AZ us-east-1b"
  value       = aws_subnet.private_1b.id
}

output "private_subnet_1a_cidr" {
  description = "CIDR block for private subnet 1a"
  value       = aws_subnet.private_1a.cidr_block
}

output "private_subnet_1b_cidr" {
  description = "CIDR block for private subnet 1b"
  value       = aws_subnet.private_1b.cidr_block
}

# RDS Outputs
output "rds_endpoint" {
  description = "RDS multi-AZ instance endpoint (addresses CC6.7 - Encryption in transit)"
  value       = aws_db_instance.main.endpoint
}

output "rds_instance_id" {
  description = "RDS instance identifier"
  value       = aws_db_instance.main.id
}

output "rds_arn" {
  description = "ARN of the RDS instance (addresses CC6.1 - Access control tracking)"
  value       = aws_db_instance.main.arn
}

output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.main.port
}

output "rds_engine" {
  description = "RDS database engine"
  value       = aws_db_instance.main.engine
}

output "rds_engine_version" {
  description = "RDS database engine version"
  value       = aws_db_instance.main.engine_version
}

output "rds_multi_az" {
  description = "Whether RDS is deployed across multiple availability zones (addresses A1 - Availability)"
  value       = aws_db_instance.main.multi_az
}

output "rds_backup_retention_days" {
  description = "Number of days RDS backups are retained (addresses PI1 - Processing Integrity)"
  value       = aws_db_instance.main.backup_retention_period
}

output "rds_backup_window" {
  description = "Preferred backup window for RDS"
  value       = aws_db_instance.main.backup_window
}

# RDS Security Group Outputs
output "rds_security_group_id" {
  description = "Security group ID for RDS instance (addresses CC6.6 - System Boundaries)"
  value       = aws_security_group.rds.id
}

output "rds_security_group_arn" {
  description = "ARN of RDS security group"
  value       = aws_security_group.rds.arn
}

# KMS Key Outputs
output "rds_kms_key_id" {
  description = "KMS key ID for RDS encryption (addresses CC6.7 - Encryption at rest)"
  value       = aws_kms_key.rds.id
}

output "rds_kms_key_arn" {
  description = "ARN of KMS key for RDS encryption"
  value       = aws_kms_key.rds.arn
}

output "rds_kms_key_alias" {
  description = "Alias of KMS key for RDS encryption"
  value       = aws_kms_alias.rds.name
}

# RDS Parameter Group Outputs
output "rds_parameter_group_id" {
  description = "RDS parameter group identifier"
  value       = aws_db_parameter_group.main.id
}

output "rds_parameter_group_arn" {
  description = "ARN of RDS parameter group"
  value       = aws_db_parameter_group.main.arn
}

# RDS Subnet Group Outputs
output "rds_subnet_group_id" {
  description = "RDS DB subnet group identifier"
  value       = aws_db_subnet_group.main.id
}

output "rds_subnet_group_arn" {
  description = "ARN of RDS subnet group"
  value       = aws_db_subnet_group.main.arn
}

# CloudWatch Outputs
output "rds_log_group_name" {
  description = "CloudWatch log group for RDS error logs (addresses CC7.2 - Monitoring)"
  value       = aws_cloudwatch_log_group.rds_error.name
}

output "rds_log_group_arn" {
  description = "ARN of RDS CloudWatch log group"
  value       = aws_cloudwatch_log_group.rds_error.arn
}

# Enhanced Monitoring IAM Role Outputs
output "rds_monitoring_role_arn" {
  description = "ARN of IAM role for RDS Enhanced Monitoring (addresses CC7.2 - Monitoring)"
  value       = aws_iam_role.rds_monitoring.arn
}

output "rds_monitoring_role_name" {
  description = "Name of IAM role for RDS Enhanced Monitoring"
  value       = aws_iam_role.rds_monitoring.name
}

# Secrets Manager Outputs
output "rds_secret_arn" {
  description = "ARN of Secrets Manager secret for RDS credentials (addresses CC6.1 - Access control)"
  value       = aws_secretsmanager_secret.rds_credentials.arn
  sensitive   = true
}

output "rds_secret_name" {
  description = "Name of Secrets Manager secret for RDS credentials"
  value       = aws_secretsmanager_secret.rds_credentials.name
}

# Environment and Tagging Outputs
output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "resource_prefix" {
  description = "Resource naming prefix"
  value       = var.resource_prefix
}

output "common_tags" {
  description = "Common tags applied to all resources"
  value       = local.common_tags
}

# Compliance Notes Output
output "compliance_notes" {
  description = "SOC 2 compliance controls addressed by this infrastructure"
  value = {
    cc6_1_logical_access     = "RDS credentials managed via Secrets Manager with IAM role-based access"
    cc6_6_system_boundaries  = "RDS security group restricts network access to private subnets only"
    cc6_7_encryption         = "RDS encryption at rest (KMS) and in transit (SSL/TLS) enabled"
    cc7_2_monitoring         = "Enhanced monitoring enabled with CloudWatch logs and error log exports"
    a1_availability          = "Multi-AZ deployment ensures high availability and automatic failover"
    pi1_processing_integrity = "Automated backups with 30-day retention for data recovery"
  }
}
```