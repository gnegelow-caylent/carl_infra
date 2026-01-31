```hcl
# VPC and Networking Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs (Presentation Tier)"
  value       = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  description = "List of application subnet IDs (Application Tier)"
  value       = aws_subnet.app[*].id
}

output "data_subnet_ids" {
  description = "List of data subnet IDs (Data Tier)"
  value       = aws_subnet.data[*].id
}

output "public_subnet_cidrs" {
  description = "CIDR blocks of public subnets"
  value       = aws_subnet.public[*].cidr_block
}

output "app_subnet_cidrs" {
  description = "CIDR blocks of application subnets"
  value       = aws_subnet.app[*].cidr_block
}

output "data_subnet_cidrs" {
  description = "CIDR blocks of data subnets"
  value       = aws_subnet.data[*].cidr_block
}

# NAT Gateway Outputs
output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

output "nat_gateway_ips" {
  description = "List of Elastic IPs for NAT Gateways"
  value       = aws_eip.nat[*].public_ip
}

# Security Groups
output "alb_security_group_id" {
  description = "Security group ID for Application Load Balancer"
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "Security group ID for ECS Fargate tasks"
  value       = aws_security_group.ecs.id
}

output "rds_security_group_id" {
  description = "Security group ID for RDS database"
  value       = aws_security_group.rds.id
}

# Application Load Balancer Outputs
output "alb_id" {
  description = "The ID of the Application Load Balancer"
  value       = aws_lb.main.id
}

output "alb_arn" {
  description = "The ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "alb_dns_name" {
  description = "The DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "The canonical hosted zone ID of the ALB"
  value       = aws_lb.main.zone_id
}

output "alb_target_group_arn" {
  description = "The ARN of the ALB target group"
  value       = aws_lb_target_group.app.arn
}

output "alb_listener_arn" {
  description = "The ARN of the ALB listener"
  value       = aws_lb_listener.app.arn
}

# ECS Cluster and Service Outputs
output "ecs_cluster_id" {
  description = "The ID of the ECS cluster"
  value       = aws_ecs_cluster.main.id
}

output "ecs_cluster_arn" {
  description = "The ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "ecs_cluster_name" {
  description = "The name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_id" {
  description = "The ID of the ECS service"
  value       = aws_ecs_service.app.id
}

output "ecs_service_arn" {
  description = "The ARN of the ECS service"
  value       = aws_ecs_service.app.service_registries
}

output "ecs_task_definition_arn" {
  description = "The ARN of the ECS task definition"
  value       = aws_ecs_task_definition.app.arn
}

output "ecs_task_definition_revision" {
  description = "The revision of the ECS task definition"
  value       = aws_ecs_task_definition.app.revision
}

output "ecs_task_execution_role_arn" {
  description = "The ARN of the ECS task execution IAM role"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

output "ecs_task_role_arn" {
  description = "The ARN of the ECS task IAM role (least privilege)"
  value       = aws_iam_role.ecs_task_role.arn
}

# Auto Scaling Outputs
output "autoscaling_target_id" {
  description = "The ID of the autoscaling target"
  value       = aws_appautoscaling_target.ecs_target.id
}

output "autoscaling_policy_cpu_arn" {
  description = "The ARN of the CPU-based autoscaling policy"
  value       = aws_appautoscaling_policy.ecs_policy_cpu.arn
}

output "autoscaling_policy_memory_arn" {
  description = "The ARN of the memory-based autoscaling policy"
  value       = aws_appautoscaling_policy.ecs_policy_memory.arn
}

# RDS Database Outputs
output "rds_endpoint" {
  description = "The connection endpoint for the RDS database"
  value       = aws_db_instance.main.endpoint
}

output "rds_address" {
  description = "The hostname of the RDS database"
  value       = aws_db_instance.main.address
}

output "rds_port" {
  description = "The port of the RDS database"
  value       = aws_db_instance.main.port
}

output "rds_database_name" {
  description = "The name of the default database"
  value       = aws_db_instance.main.db_name
}

output "rds_arn" {
  description = "The ARN of the RDS database instance"
  value       = aws_db_instance.main.arn
}

output "rds_resource_id" {
  description = "The RDS resource ID"
  value       = aws_db_instance.main.resource_id
}

output "rds_multi_az" {
  description = "Whether the RDS instance is Multi-AZ enabled"
  value       = aws_db_instance.main.multi_az
}

output "rds_backup_retention_days" {
  description = "The number of days backups are retained"
  value       = aws_db_instance.main.backup_retention_period
}

output "rds_backup_window" {
  description = "The daily time window for automated backups"
  value       = aws_db_instance.main.backup_window
}

output "rds_maintenance_window" {
  description = "The maintenance window for the RDS instance"
  value       = aws_db_instance.main.maintenance_window
}

output "rds_subnet_group_id" {
  description = "The ID of the RDS subnet group"
  value       = aws_db_subnet_group.main.id
}

output "rds_subnet_group_arn" {
  description = "The ARN of the RDS subnet group"
  value       = aws_db_subnet_group.main.arn
}

# KMS Encryption Outputs
output "rds_kms_key_id" {
  description = "The ID