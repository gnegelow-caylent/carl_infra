```hcl
# ============================================================================
# General Configuration Variables
# ============================================================================

variable "resource_prefix" {
  description = "Prefix for all resource names to ensure uniqueness and organization"
  type        = string
  default     = "test"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric with hyphens, max 20 characters"
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod) for resource tagging and configuration"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.aws_region))
    error_message = "AWS region must be a valid region format (e.g., us-east-1)"
  }
}

variable "tags" {
  description = "Common tags applied to all resources for organization and cost tracking"
  type        = map(string)
  default = {
    Terraform   = "true"
    Environment = "dev"
    Project     = "web-app"
  }
}

# ============================================================================
# VPC and Networking Variables
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC (10.2.0.0/16 for this deployment)"
  type        = string
  default     = "10.2.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block"
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs to S3 for compliance monitoring and troubleshooting"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_retention_days" {
  description = "Number of days to retain VPC Flow Logs in S3"
  type        = number
  default     = 30

  validation {
    condition     = var.vpc_flow_logs_retention_days > 0 && var.vpc_flow_logs_retention_days <= 3650
    error_message = "Retention days must be between 1 and 3650"
  }
}

variable "availability_zones_count" {
  description = "Number of Availability Zones for redundancy (minimum 2 for HA)"
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zones_count >= 2 && var.availability_zones_count <= 3
    error_message = "Must deploy across 2-3 Availability Zones for redundancy"
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateways for outbound internet access from private subnets"
  type        = bool
  default     = true
}

# ============================================================================
# EC2 and Auto Scaling Variables
# ============================================================================

variable "instance_type" {
  description = "EC2 instance type for web application servers (t3.medium recommended for redundancy)"
  type        = string
  default     = "t3.medium"

  validation {
    condition     = contains(["t3.micro", "t3.small", "t3.medium", "t3.large"], var.instance_type)
    error_message = "Instance type must be t3.micro, t3.small, t3.medium, or t3.large"
  }
}

variable "ami_id" {
  description = "AMI ID for EC2 instances (Amazon Linux 2 or Ubuntu LTS recommended)"
  type        = string
  default     = ""

  validation {
    condition     = var.ami_id == "" || can(regex("^ami-[0-9a-f]{17}$", var.ami_id))
    error_message = "AMI ID must be empty or a valid AMI format (ami-xxxxxxxxxxxxxxxxx)"
  }
}

variable "key_name" {
  description = "EC2 Key Pair name for SSH access to instances"
  type        = string
  default     = ""
}

variable "asg_min_size" {
  description = "Minimum number of instances in Auto Scaling Group"
  type        = number
  default     = 2

  validation {
    condition     = var.asg_min_size >= 2
    error_message = "Minimum size must be at least 2 for redundancy"
  }
}

variable "asg_max_size" {
  description = "Maximum number of instances in Auto Scaling Group"
  type        = number
  default     = 4

  validation {
    condition     = var.asg_max_size >= var.asg_min_size && var.asg_max_size <= 10
    error_message = "Maximum size must be >= minimum size and <= 10"
  }
}

variable "asg_desired_capacity" {
  description = "Desired number of instances in Auto Scaling Group"
  type        = number
  default     = 2

  validation {
    condition     = var.asg_desired_capacity >= 2 && var.asg_desired_capacity <= 4
    error_message = "Desired capacity must be between 2 and 4"
  }
}

variable "health_check_type" {
  description = "Health check type for Auto Scaling Group (ELB or EC2)"
  type        = string
  default     = "ELB"

  validation {
    condition     = contains(["ELB", "EC2"], var.health_check_type)
    error_message = "Health check type must be ELB or EC2"
  }
}

variable "health_check_grace_period" {
  description = "Time in seconds for instance to warm up before health checks begin"
  type        = number
  default     = 300

  validation {
    condition     = var.health_check_grace_period >= 0 && var.health_check_grace_period <= 3600
    error_message = "Grace period must be between 0 and 3600 seconds"
  }
}

# ============================================================================
# Application Load Balancer Variables
# ============================================================================

variable "alb_internal" {
  description = "Whether the ALB is internal (false for internet-facing)"
  type        = bool
  default     = false
}

variable "alb_enable_deletion_protection" {
  description = "Enable deletion protection for the ALB"
  type        = bool
  default     = false
}

variable "alb_enable_http2" {
  description = "Enable HTTP/2 on the ALB"
  type        = bool
  default     = true
}

variable "alb_enable_cross_zone_load_balancing" {
  description = "Enable cross-zone load balancing for the ALB"
  type        = bool
  default     = true
}

variable "target_group_port" {
  description = "Port on which targets receive traffic from the ALB"
  type        = number
  default     = 80

  validation {
    condition     = var.target_group_port >= 1 && var.target_group_port <= 65535
    error_message = "Target group port must be between 1 and 65535"
  }
}

variable "target_group_protocol" {
  description = "Protocol for target group (HTTP or HTTPS)"
  type        = string
  default     = "HTTP"

  validation {
    condition     = contains(["HTTP", "HTTPS"], var.target_group_protocol)
    error_message = "Target group protocol must be HTTP or HTTPS"
  }
}

variable "health_check_enabled" {
  description = "Enable health checks on the target group"
  type        = bool
  default     = true
}

variable "health_check_healthy_threshold" {
  description = "Number of consecutive health checks successes required to mark target healthy"
  type        = number
  default     = 2

  validation {
    condition     = var.health_check_healthy_threshold >= 2 && var.health_check_healthy_threshold <= 10
    error_message = "Healthy threshold must be between 2 and 10"
  }
}

variable "health_check_unhealthy_threshold" {
  description = "Number of consecutive health check failures required to mark target unhealthy"
  type        = number
  default     = 2

  validation {
    condition     = var.health_check_unhealthy_threshold >= 2 && var.health_check_unhealthy_threshold <= 10
    error_message = "Unhealthy threshold must be between 2 and 10"
  }
}

variable "health_check_interval" {
  description = "Approximate amount of time in seconds between health checks"
  type        = number
  default     = 30

  validation {
    condition     = var.health_check_interval >= 5 && var.health_check_interval <= 300
    error_message = "Health check interval must be between 5 and 300 seconds"
  }
}

variable "health_check_timeout" {
  description = "Amount of time in seconds to wait for a health check response"
  type        = number
  default     = 5

  validation {
    condition     = var.health_check_timeout >= 2 && var.health_check_timeout <= 120
    error_message = "Health check timeout must be between 2 and 120 seconds"
  }
}

# ============================================================================
# RDS Database Variables
# ============================================================================

variable "db_instance_class" {
  description = "RDS instance class for database (db.t3.micro recommended for dev)"
  type        = string
  default     = "db.t3.micro"

  validation {
    condition     = can(regex("^db\\.t3\\.(micro|small|medium|large)$", var.db_instance_class))
    error_message = "DB instance class must be a valid t3 instance type"
  }
}

variable "db_engine" {
  description = "RDS database engine (mysql, postgres, mariadb)"
  type        = string
  default     = "mysql"

  validation {
    condition     = contains(["mysql", "postgres", "mariadb"], var.db_engine)
    error_message = "DB engine must be mysql, postgres, or mariadb"
  }
}

variable "db_engine_version" {
  description = "Version of the database engine"
  type        = string
  default     = "8.0"
}

variable "db_name" {
  description = "Name of the initial database to create"
  type        = string
  default     = "appdb"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.db_name))
    error_message = "DB name must start with a letter and contain only alphanumeric characters and underscores"
  }
}

variable "db_username" {
  description = "Master username for the database"
  type        = string
  default     = "admin"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.db_username))
    error_message = "DB username must start with a letter and contain only alphanumeric characters and underscores"
  }
}

variable "db_password" {
  description = "Master password for the database (use AWS Secrets Manager in production)"
  type        = string
  sensitive   = true
  default     = ""

  validation {
    condition     = var.db_password == "" || length(var.db_password) >= 8
    error_message = "DB password must be at least 8 characters or use Secrets Manager"
  }
}

variable "db_allocated_storage" {
  description = "Allocated storage for RDS in GB"
  type        = number
  default     = 20

  validation {
    condition     = var.db_allocated_storage >= 20 && var.db_allocated_storage <= 65536
    error_message = "Allocated storage must be between 20 and 65536 GB"
  }
}

variable "db_multi_az" {
  description = "Enable Multi-AZ deployment for automatic failover (<2min failover time)"
  type        = bool
  default     = true
}

variable "db_backup_retention_period" {
  description = "Number of days to retain database backups"
  type        = number
  default     = 7

  validation {
    condition     = var.db_backup_retention_period >= 1 && var.db_backup_retention_period <= 35
    error_message = "Backup retention period must be between 1 and 35 days"
  }
}

variable "db_backup_window" {
  description = "Preferred backup window in UTC (HH:MM-HH:MM format)"
  type        = string
  default     = "03:00-04:00"
}

variable "db_maintenance_window" {
  description = "Preferred maintenance window (ddd:HH:MM-ddd:HH:MM format)"
  type        = string
  default     = "sun:04:00-sun:05:00"
}

variable "db_enable_encryption" {
  description = "Enable encryption at rest for the database"
  type        = bool
  default     = true
}

variable "db_enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for the database"
  type        = bool
  default     = true
}

variable "db_monitoring_interval" {
  description = "Monitoring interval in seconds (0 to disable, 1, 5, 10, 15, 30, 60)"
  type        = number
  default     = 60

  validation {
    condition     = contains([0, 1, 5, 10, 15, 30, 60], var.db_monitoring_interval)
    error_message = "Monitoring interval must be 0, 1, 5, 10, 15, 30, or 60"
  }
}

variable "db_enable_deletion_protection" {
  description = "Enable deletion protection for the database"
  type        = bool
  default     = true
}

# ============================================================================
# S3 and Storage Variables
# ============================================================================

variable "enable_s3_versioning" {
  description = "Enable versioning on S3 buckets for compliance and recovery"
  type        = bool
  default     = true
}

variable "enable_s3_encryption" {
  description = "Enable server-side encryption on S3 buckets"
  type        = bool
  default     = true
}

variable "s3_encryption_algorithm" {
  description = "S3 encryption algorithm (AES256 or aws:kms)"
  type        = string
  default     = "AES256"

  validation {
    condition     = contains(["AES256", "aws:kms"], var.s3_encryption_algorithm)
    error_message = "Encryption algorithm must be AES256 or aws:kms"
  }
}

variable "enable_s3_block_public_access" {
  description = "Block all public access to S3 buckets"
  type        = bool
  default     = true
}

# ============================================================================
# Monitoring and Logging Variables
# ============================================================================

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for monitoring application and infrastructure health"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""

  validation {
    condition     = var.alarm