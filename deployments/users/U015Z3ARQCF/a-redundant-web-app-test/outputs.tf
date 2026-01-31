```hcl
# VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

# Public Subnet Outputs
output "public_subnet_az1_id" {
  description = "The ID of the public subnet in AZ1"
  value       = aws_subnet.public_az1.id
}

output "public_subnet_az2_id" {
  description = "The ID of the public subnet in AZ2"
  value       = aws_subnet.public_az2.id
}

output "public_subnet_ids" {
  description = "List of all public subnet IDs"
  value       = [aws_subnet.public_az1.id, aws_subnet.public_az2.id]
}

# Application Subnet Outputs
output "app_subnet_az1_id" {
  description = "The ID of the application subnet in AZ1"
  value       = aws_subnet.app_az1.id
}

output "app_subnet_az2_id" {
  description = "The ID of the application subnet in AZ2"
  value       = aws_subnet.app_az2.id
}

output "app_subnet_ids" {
  description = "List of all application subnet IDs"
  value       = [aws_subnet.app_az1.id, aws_subnet.app_az2.id]
}

# Data Subnet Outputs
output "data_subnet_az1_id" {
  description = "The ID of the data subnet in AZ1"
  value       = aws_subnet.data_az1.id
}

output "data_subnet_az2_id" {
  description = "The ID of the data subnet in AZ2"
  value       = aws_subnet.data_az2.id
}

output "data_subnet_ids" {
  description = "List of all data subnet IDs"
  value       = [aws_subnet.data_az1.id, aws_subnet.data_az2.id]
}

# Internet Gateway Output
output "internet_gateway_id" {
  description = "The ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

# NAT Gateway Outputs
output "nat_gateway_az1_id" {
  description = "The ID of the NAT Gateway in AZ1"
  value       = aws_nat_gateway.az1.id
}

output "nat_gateway_az2_id" {
  description = "The ID of the NAT Gateway in AZ2"
  value       = aws_nat_gateway.az2.id
}

output "nat_gateway_az1_eip" {
  description = "The Elastic IP address of the NAT Gateway in AZ1"
  value       = aws_eip.nat_az1.public_ip
}

output "nat_gateway_az2_eip" {
  description = "The Elastic IP address of the NAT Gateway in AZ2"
  value       = aws_eip.nat_az2.public_ip
}

# Security Group Outputs
output "alb_security_group_id" {
  description = "The ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "The ID of the application security group"
  value       = aws_security_group.app.id
}

output "rds_security_group_id" {
  description = "The ID of the RDS security group"
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
  description = "The zone ID of the Application Load Balancer"
  value       = aws_lb.main.zone_id
}

output "alb_url" {
  description = "The URL of the Application Load Balancer"
  value       = "http://${aws_lb.main.dns_name}"
}

# Target Group Outputs
output "target_group_arn" {
  description = "The ARN of the target group"
  value       = aws_lb_target_group.app.arn
}

output "target_group_id" {
  description = "The ID of the target group"
  value       = aws_lb_target_group.app.id
}

# Auto Scaling Group Outputs
output "asg_name" {
  description = "The name of the Auto Scaling Group"
  value       = aws_autoscaling_group.app.name
}

output "asg_arn" {
  description = "The ARN of the Auto Scaling Group"
  value       = aws_autoscaling_group.app.arn
}

output "asg_min_size" {
  description = "The minimum size of the Auto Scaling Group"
  value       = aws_autoscaling_group.app.min_size
}

output "asg_max_size" {
  description = "The maximum size of the Auto Scaling Group"
  value       = aws_autoscaling_group.app.max_size
}

output "asg_desired_capacity" {
  description = "The desired capacity of the Auto Scaling Group"
  value       = aws_autoscaling_group.app.desired_capacity
}

# Launch Template Outputs
output "launch_template_id" {
  description = "The ID of the launch template"
  value       = aws_launch_template.app.id
}

output "launch_template_latest_version" {
  description = "The latest version of the launch template"
  value       = aws_launch_template.app.latest_version_number
}

# RDS Outputs
output "rds_endpoint" {
  description = "The connection endpoint for the RDS database"
  value       = aws_db_instance.main.endpoint
}

output "rds_address" {
  description = "The address of the RDS database"
  value       = aws_db_instance.main.address
}

output "rds_port" {
  description = "The port of the RDS database"
  value       = aws_db_instance.main.port
}

output "rds_database_name" {
  description = "The name of the database"
  value       = aws_db_instance.main.db_name
}

output "rds_instance_id" {
  description = "The instance ID of the RDS database"
  value       = aws_db_instance.main.id
}

output "rds_arn" {
  description = "The ARN of the RDS database"
  value       = aws_db_instance.main.arn
}

output "rds_master_username" {
  description = "The master username for the RDS database"
  value       = aws_db_instance.main.username
  sensitive   = true
}

output "rds_multi_az" {
  description = "Whether the RDS database is Multi-AZ"
  value       = aws_db_instance.main.multi_az
}

# S3 Bucket Outputs (VPC Flow Logs)
output "flow_logs_bucket_id" {
  description = "The ID of the S3 bucket for VPC Flow Logs"
  value       = aws_s3_bucket.flow_logs.id
}

output "flow_logs_bucket_arn" {
  description = "The ARN of the S3 bucket for VPC Flow Logs"
  value       = aws_s