```hcl
# ============================================================================
# GENERAL CONFIGURATION
# ============================================================================

variable "resource_prefix" {
  description = "Prefix for all AWS resources"
  type        = string
  default     = "test"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric with hyphens, max 20 characters."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.aws_region))
    error_message = "Invalid AWS region format."
  }
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Environment = "dev"
  }
}

# ============================================================================
# VPC & NETWORKING
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.21.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "availability_zones" {
  description = "Number of availability zones for multi-AZ deployment"
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zones >= 2 && var.availability_zones <= 3
    error_message = "Must deploy across 2-3 availability zones."
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateways for private subnet internet access"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring (CC7.2)"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_retention_days" {
  description = "CloudWatch Logs retention period for VPC Flow Logs"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.vpc_flow_logs_retention_days)
    error_message = "Must be a valid CloudWatch Logs retention period."
  }
}

variable "enable_s3_endpoint" {
  description = "Enable S3 Gateway Endpoint (free, reduces NAT costs)"
  type        = bool
  default     = true
}

variable "enable_dynamodb_endpoint" {
  description = "Enable DynamoDB Gateway Endpoint (free)"
  type        = bool
  default     = true
}

# ============================================================================
# APPLICATION LOAD BALANCER
# ============================================================================

variable "alb_enable_deletion_protection" {
  description = "Enable deletion protection for ALB"
  type        = bool
  default     = false
}

variable "alb_enable_http2" {
  description = "Enable HTTP/2 on ALB"
  type        = bool
  default     = true
}

variable "alb_enable_cross_zone_load_balancing" {
  description = "Enable cross-zone load balancing"
  type        = bool
  default     = true
}

variable "alb_idle_timeout" {
  description = "ALB idle timeout in seconds"
  type        = number
  default     = 60

  validation {
    condition     = var.alb_idle_timeout >= 1 && var.alb_idle_timeout <= 4000
    error_message = "ALB idle timeout must be between 1 and 4000 seconds."
  }
}

# ============================================================================
# ECS FARGATE CONFIGURATION
# ============================================================================

variable "ecs_container_name" {
  description = "Name of the ECS container"
  type        = string
  default     = "app"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,255}$", var.ecs_container_name))
    error_message = "Container name must be alphanumeric with hyphens/underscores, max 255 characters."
  }
}

variable "ecs_container_image" {
  description = "Docker image URI for ECS tasks"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9./:_-]+$", var.ecs_container_image))
    error_message = "Container image must be a valid Docker image URI."
  }
}

variable "ecs_container_port" {
  description = "Port exposed by container"
  type        = number
  default     = 8080

  validation {
    condition     = var.ecs_container_port >= 1 && var.ecs_container_port <= 65535
    error_message = "Container port must be between 1 and 65535."
  }
}

variable "ecs_task_cpu" {
  description = "ECS task CPU units (256=0.25vCPU, 512=0.5vCPU, 1024=1vCPU)"
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.ecs_task_cpu)
    error_message = "Task CPU must be 256, 512, 1024, 2048, or 4096."
  }
}

variable "ecs_task_memory" {
  description = "ECS task memory in MB"
  type        = number
  default     = 1024

  validation {
    condition     = contains([512, 1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192], var.ecs_task_memory)
    error_message = "Task memory must be a valid Fargate memory value (512-8192 MB)."
  }
}

variable "ecs_desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 2

  validation {
    condition     = var.ecs_desired_count >= 1 && var.ecs_desired_count <= 10
    error_message = "Desired task count must be between 1 and 10."
  }
}

variable "ecs_min_capacity" {
  description = "Minimum number of ECS tasks for auto-scaling"
  type        = number
  default     = 2

  validation {
    condition     = var.ecs_min_capacity >= 1 && var.ecs_min_capacity <= 10
    error_message = "Minimum capacity must be between 1 and 10."
  }
}

variable "ecs_max_capacity" {
  description = "Maximum number of ECS tasks for auto-scaling"
  type        = number
  default     = 10

  validation {
    condition     = var.ecs_max_capacity >= 1 && var.ecs_max_capacity <= 10
    error_message = "Maximum capacity must be between 1 and 10."
  }
}

variable "ecs_target_cpu_utilization" {
  description = "Target CPU utilization percentage for auto-scaling"
  type        = number
  default     = 70

  validation {
    condition     = var.ecs_target_cpu_utilization > 0 && var.ecs_target_cpu_utilization <= 100
    error_message = "Target CPU utilization must be between 1 and 100."
  }
}

variable "ecs_target_memory_utilization" {
  description = "Target memory utilization percentage for auto-scaling"
  type        = number
  default     = 80

  validation {
    condition     = var.ecs_target_memory_utilization > 0 && var.ecs_target_memory_utilization <= 100
    error_message = "Target memory utilization must be between 1 and 100."
  }
}

variable "ecs_enable_execute_command" {
  description = "Enable ECS Exec for container debugging (CC6.6)"
  type        = bool
  default     = false
}

variable "ecs_enable_container_insights" {
  description = "Enable CloudWatch Container Insights for monitoring"
  type        = bool
  default     = true
}

# ============================================================================
# RDS CONFIGURATION
# ============================================================================

variable "rds_engine" {
  description = "RDS database engine (postgres or mysql)"
  type        = string
  default     = "postgres"

  validation {
    condition     = contains(["postgres", "mysql"], var.rds_engine)
    error_message = "RDS engine must be postgres or mysql."
  }
}

variable "rds_engine_version" {
  description = "RDS database engine version"
  type        = string
  default     = "15.3"
}

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.small"

  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.rds_instance_class))
    error_message = "RDS instance class must be a valid AWS instance type."
  }
}

variable "rds_allocated_storage" {
  description = "Allocated storage for RDS in GB"
  type        = number
  default     = 20

  validation {
    condition     = var.rds_allocated_storage >= 20 && var.rds_allocated_storage <= 65536
    error_message = "Allocated storage must be between 20 and 65536 GB."
  }
}

variable "rds_max_allocated_storage" {
  description = "Maximum allocated storage for RDS autoscaling in GB"
  type        = number
  default     = 100

  validation {
    condition     = var.rds_max_allocated_storage >= 20 && var.rds_max_allocated_storage <= 65536
    error_message = "Max allocated storage must be between 20 and 65536 GB."
  }
}

variable "rds_database_name" {
  description = "Initial database name"
  type        = string
  default     = "appdb"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.rds_database_name))
    error_message = "Database name must start with letter and contain only alphanumeric/underscore."
  }
}

variable "rds_username" {
  description = "Master username for RDS (stored in Secrets Manager)"
  type        = string
  default     = "dbadmin"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.rds_username))
    error_message = "Username must start with letter and contain only alphanumeric/underscore."
  }

  sensitive = true
}

variable "rds_backup_retention_days" {
  description = "RDS backup retention period in days (SOC 2 requirement)"
  type        = number
  default     = 30