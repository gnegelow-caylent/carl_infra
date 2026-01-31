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
    error_message = "Resource prefix must be lowercase alphanumeric and hyphens, max 20 characters"
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
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
  description = "Common tags applied to all resources for organization and billing"
  type        = map(string)
  default = {
    Terraform   = "true"
    Environment = "dev"
    Application = "iot-serverless"
  }
}

# ============================================================================
# Networking Variables
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.1.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block"
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network traffic monitoring and compliance"
  type        = bool
  default     = true
}

variable "vpc_id" {
  description = "Existing VPC ID to use (leave empty to create new VPC)"
  type        = string
  default     = ""
}

# ============================================================================
# AWS IoT Core Variables
# ============================================================================

variable "iot_thing_group_name" {
  description = "Name of the IoT Thing Group for device organization"
  type        = string
  default     = "iot-devices"

  validation {
    condition     = can(regex("^[a-zA-Z0-9:_-]{1,128}$", var.iot_thing_group_name))
    error_message = "IoT Thing Group name must be 1-128 characters, alphanumeric with :_- allowed"
  }
}

variable "iot_policy_name" {
  description = "Name of the IoT policy for device certificate authorization"
  type        = string
  default     = "iot-device-policy"

  validation {
    condition     = can(regex("^[a-zA-Z0-9:_-]{1,128}$", var.iot_policy_name))
    error_message = "IoT policy name must be 1-128 characters, alphanumeric with :_- allowed"
  }
}

variable "iot_enable_logging" {
  description = "Enable AWS IoT Core logging to CloudWatch for audit and troubleshooting"
  type        = bool
  default     = true
}

# ============================================================================
# Lambda Variables
# ============================================================================

variable "lambda_runtime" {
  description = "Lambda runtime for IoT message processing"
  type        = string
  default     = "python3.11"

  validation {
    condition     = contains(["python3.11", "python3.12", "nodejs18.x", "nodejs20.x"], var.lambda_runtime)
    error_message = "Lambda runtime must be a supported Python or Node.js version"
  }
}

variable "lambda_memory_size" {
  description = "Memory allocation for Lambda function in MB"
  type        = number
  default     = 256

  validation {
    condition     = contains([128, 256, 512, 1024, 1536, 2048, 3008], var.lambda_memory_size)
    error_message = "Lambda memory must be 128, 256, 512, 1024, 1536, 2048, or 3008 MB"
  }
}

variable "lambda_timeout" {
  description = "Timeout for Lambda function execution in seconds"
  type        = number
  default     = 60

  validation {
    condition     = var.lambda_timeout > 0 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds"
  }
}

variable "lambda_enable_vpc" {
  description = "Enable Lambda VPC configuration for on-premises connectivity"
  type        = bool
  default     = false
}

# ============================================================================
# DynamoDB Variables
# ============================================================================

variable "dynamodb_table_name" {
  description = "DynamoDB table name for storing device state and metadata"
  type        = string
  default     = "iot-device-state"

  validation {
    condition     = can(regex("^[a-zA-Z0-9._-]{3,255}$", var.dynamodb_table_name))
    error_message = "DynamoDB table name must be 3-255 characters, alphanumeric with ._- allowed"
  }
}

variable "dynamodb_billing_mode" {
  description = "DynamoDB billing mode (PAY_PER_REQUEST for on-demand, PROVISIONED for reserved)"
  type        = string
  default     = "PAY_PER_REQUEST"

  validation {
    condition     = contains(["PAY_PER_REQUEST", "PROVISIONED"], var.dynamodb_billing_mode)
    error_message = "DynamoDB billing mode must be PAY_PER_REQUEST or PROVISIONED"
  }
}

variable "dynamodb_enable_ttl" {
  description = "Enable TTL on DynamoDB table for automatic data expiration"
  type        = bool
  default     = true
}

variable "dynamodb_ttl_attribute" {
  description = "Attribute name for DynamoDB TTL"
  type        = string
  default     = "expiration_time"
}

variable "dynamodb_enable_encryption" {
  description = "Enable encryption at rest for DynamoDB table (SOC 2 CC6.1 compliance)"
  type        = bool
  default     = true
}

variable "dynamodb_enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for DynamoDB table"
  type        = bool
  default     = true
}

# ============================================================================
# S3 Variables
# ============================================================================

variable "s3_bucket_name" {
  description = "S3 bucket name for storing historical IoT data"
  type        = string
  default     = ""

  validation {
    condition     = var.s3_bucket_name == "" || can(regex("^[a-z0-9.-]{3,63}$", var.s3_bucket_name))
    error_message = "S3 bucket name must be 3-63 lowercase alphanumeric characters with . and - allowed"
  }
}

variable "s3_enable_versioning" {
  description = "Enable S3 bucket versioning for data protection"
  type        = bool
  default     = true
}

variable "s3_enable_encryption" {
  description = "Enable S3 server-side encryption at rest (SOC 2 CC6.1 compliance)"
  type        = bool
  default     = true
}

variable "s3_encryption_algorithm" {
  description = "S3 encryption algorithm (AES256 or aws:kms)"
  type        = string
  default     = "AES256"

  validation {
    condition     = contains(["AES256", "aws:kms"], var.s3_encryption_algorithm)
    error_message = "S3 encryption algorithm must be AES256 or aws:kms"
  }
}

variable "s3_enable_public_access_block" {
  description = "Block all public access to S3 bucket (security best practice)"
  type        = bool
  default     = true
}

variable "s3_lifecycle_glacier_days" {
  description = "Number of days before transitioning objects to Glacier storage class"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_lifecycle_glacier_days > 0 && var.s3_lifecycle_glacier_days <= 3650
    error_message = "Glacier transition days must be between 1 and 3650"
  }
}

variable "s3_lifecycle_expiration_days" {
  description = "Number of days before permanently deleting objects from S3"
  type        = number
  default     = 2555

  validation {
    condition     = var.s3_lifecycle_expiration_days > 0 && var.s3_lifecycle_expiration_days <= 3650
    error_message = "Expiration days must be between 1 and 3650"
  }
}

variable "s3_enable_logging" {
  description = "Enable S3 access logging for audit trail (SOC 2 CC7 compliance)"
  type        = bool
  default     = true
}

# ============================================================================
# CloudWatch Variables
# ============================================================================

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_log_retention_days)
    error_message = "CloudWatch log retention must be a valid AWS retention period"
  }
}

variable "cloudwatch_log_group_name" {
  description = "CloudWatch Log Group name for IoT and Lambda logs"
  type        = string
  default     = "/aws/iot/serverless"

  validation {
    condition     = can(regex("^[\\.\\-_/#A-Za-z0-9]{1,256}$", var.cloudwatch_log_group_name))
    error_message = "CloudWatch Log Group name must be 1-256 characters"
  }
}

variable "cloudwatch_enable_encryption" {
  description = "Enable encryption for CloudWatch Logs (SOC 2 CC6.1 compliance)"
  type        = bool
  default     = true
}

# ============================================================================
# Monitoring and Compliance Variables
# ============================================================================

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for audit logging and compliance (SOC 2 CC7 requirement)"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for threat detection and security monitoring"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring and configuration tracking"
  type        = bool
  default     = true
}

variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""

  validation {
    condition     = var.alarm_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.alarm_email))
    error_message = "Alarm email must be a valid email address or empty"
  }
}

# ============================================================================
# IoT Device Configuration Variables
# ============================================================================

variable "max_device_count" {
  description = "Expected maximum number of IoT devices (for capacity planning)"
  type        = number
  default     = 10000

  validation {
    condition     = var.max_device_count > 0 && var.max_device_count <= 1000000
    error_message = "Max device count must be between 1 and 1,000,000"
  }
}

variable "message_retention_hours" {
  description = "How long to retain device messages in DynamoDB before archiving to S3"
  type        = number
  default     = 24

  validation {
    condition     = var.message_retention_hours > 0 && var.message_retention_hours <= 8760
    error_message = "Message retention must be between 1 and 8760 hours"
  }
}

variable "enable_device_certificate_rotation" {
  description = "Enable automatic device certificate rotation for security (SOC 2 CC6.6)"
  type        = bool
  default     = true
}

variable "certificate_rotation_days" {
  description = "Number of days before rotating device certificates"
  type        = number
  default     = 365

  validation {
    condition     = var.certificate_rotation_days > 0 && var.certificate_rotation_days <= 3650
    error_message = "Certificate rotation days must be between 1 and 3650"
  }
}
```