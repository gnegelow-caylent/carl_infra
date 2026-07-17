```hcl
# ============================================================================
# General Configuration Variables
# ============================================================================

variable "resource_prefix" {
  description = "Prefix for all resource names to ensure uniqueness and organization"
  type        = string
  default     = "carl"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric with hyphens, max 20 characters"
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"

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
  description = "Common tags applied to all resources for billing, compliance, and organization"
  type        = map(string)
  default = {
    Terraform   = "true"
    Environment = "prod"
    ManagedBy   = "CARL"
  }

  validation {
    condition     = length(var.tags) > 0
    error_message = "Tags map must not be empty"
  }
}

# ============================================================================
# VPC and Networking Variables
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for VPC (addresses CC6.6 - System Boundaries)"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block"
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring and compliance (addresses CC7.2 - Monitoring)"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_retention_days" {
  description = "CloudWatch Logs retention period for VPC Flow Logs in days (minimum 7 years for SOC 2)"
  type        = number
  default     = 2555

  validation {
    condition     = var.vpc_flow_logs_retention_days >= 2555
    error_message = "VPC Flow Logs retention must be at least 2555 days (7 years) for SOC 2 compliance"
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet outbound internet access"
  type        = bool
  default     = true
}

# ============================================================================
# RDS Database Variables
# ============================================================================

variable "db_instance_class" {
  description = "RDS instance class for compute and memory allocation"
  type        = string
  default     = "db.t3.small"

  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.db_instance_class))
    error_message = "DB instance class must be a valid RDS instance type (e.g., db.t3.small)"
  }
}

variable "db_engine" {
  description = "RDS database engine type"
  type        = string
  default     = "postgres"

  validation {
    condition     = contains(["postgres", "mysql", "mariadb", "oracle-se2", "sqlserver-se"], var.db_engine)
    error_message = "DB engine must be postgres, mysql, mariadb, oracle-se2, or sqlserver-se"
  }
}

variable "db_engine_version" {
  description = "RDS database engine version"
  type        = string
  default     = "15.3"
}

variable "db_name" {
  description = "Initial database name created in RDS instance"
  type        = string
  default     = "carldb"

  validation {
    condition     = can(regex("^[a-z0-9_]{1,63}$", var.db_name))
    error_message = "Database name must be lowercase alphanumeric with underscores, max 63 characters"
  }
}

variable "db_username" {
  description = "Master username for RDS database (addresses CC6.1 - Logical Access)"
  type        = string
  default     = "admin"
  sensitive   = true

  validation {
    condition     = can(regex("^[a-zA-Z0-9_]{1,16}$", var.db_username))
    error_message = "DB username must be alphanumeric with underscores, max 16 characters"
  }
}

variable "db_password" {
  description = "Master password for RDS database - must be 8+ characters with mixed case, numbers, and symbols (addresses CC6.1 - Logical Access)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.db_password) >= 8 && can(regex("[A-Z]", var.db_password)) && can(regex("[a-z]", var.db_password)) && can(regex("[0-9]", var.db_password)) && can(regex("[!@#$%^&*]", var.db_password))
    error_message = "DB password must be 8+ characters with uppercase, lowercase, numbers, and special characters (!@#$%^&*)"
  }
}

variable "multi_az" {
  description = "Enable Multi-AZ deployment for high availability and disaster recovery (addresses A1 - Availability)"
  type        = bool
  default     = true
}

variable "storage_type" {
  description = "RDS storage type (gp3 recommended for performance and cost)"
  type        = string
  default     = "gp3"

  validation {
    condition     = contains(["gp2", "gp3", "io1", "io2"], var.storage_type)
    error_message = "Storage type must be gp2, gp3, io1, or io2"
  }
}

variable "allocated_storage" {
  description = "Initial allocated storage in GB for RDS instance"
  type        = number
  default     = 100

  validation {
    condition     = var.allocated_storage >= 20 && var.allocated_storage <= 65536
    error_message = "Allocated storage must be between 20 and 65536 GB"
  }
}

variable "enable_rds_encryption" {
  description = "Enable encryption at rest for RDS instance (addresses CC6.7 - Encryption)"
  type        = bool
  default     = true
}

variable "enable_rds_backup" {
  description = "Enable automated backups for RDS instance (addresses A1 - Availability)"
  type        = bool
  default     = true
}

variable "backup_retention_period" {
  description = "Number of days to retain RDS backups (minimum 7 days for SOC 2)"
  type        = number
  default     = 30

  validation {
    condition     = var.backup_retention_period >= 7 && var.backup_retention_period <= 35
    error_message = "Backup retention period must be between 7 and 35 days"
  }
}

variable "enable_enhanced_monitoring" {
  description = "Enable Enhanced Monitoring for RDS (addresses CC7.2 - Monitoring)"
  type        = bool
  default     = true
}

variable "monitoring_interval" {
  description = "Enhanced Monitoring interval in seconds (0 to disable, 1, 5, 10, 15, 30, 60)"
  type        = number
  default     = 60

  validation {
    condition     = contains([0, 1, 5, 10, 15, 30, 60], var.monitoring_interval)
    error_message = "Monitoring interval must be 0, 1, 5, 10, 15, 30, or 60 seconds"
  }
}

variable "enable_rds_logging" {
  description = "Enable RDS database logging for audit and compliance (addresses CC7.2 - Monitoring)"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period for RDS logs in days (minimum 7 years for SOC 2)"
  type        = number
  default     = 2555

  validation {
    condition     = var.log_retention_days >= 2555
    error_message = "Log retention must be at least 2555 days (7 years) for SOC 2 compliance"
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection to prevent accidental RDS instance deletion"
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "Skip final snapshot on RDS deletion (set to false for production)"
  type        = bool
  default     = false
}

# ============================================================================
# Security and Compliance Variables
# ============================================================================

variable "enable_rds_iam_auth" {
  description = "Enable IAM database authentication for RDS (addresses CC6.1 - Logical Access)"
  type        = bool
  default     = true
}

variable "publicly_accessible" {
  description = "Make RDS instance publicly accessible (not recommended for production)"
  type        = bool
  default     = false
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for RDS monitoring (addresses CC7.1 - Threat Detection)"
  type        = bool
  default     = true
}
```