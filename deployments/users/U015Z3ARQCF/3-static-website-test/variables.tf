```hcl
# ============================================================================
# AWS Static Website Infrastructure - Variables
# S3 + CloudFront + Route 53 Setup for 3 Static Websites
# ============================================================================

# ============================================================================
# General Configuration Variables
# ============================================================================

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.aws_region))
    error_message = "AWS region must be a valid region format (e.g., us-east-1)."
  }
}

variable "resource_prefix" {
  description = "Prefix for all AWS resources to ensure naming uniqueness"
  type        = string
  default     = "test"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric and hyphens, max 20 characters."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Project     = "static-websites"
    ManagedBy   = "terraform"
  }
}

# ============================================================================
# VPC Configuration Variables
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.3.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring and compliance"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_retention_days" {
  description = "CloudWatch Logs retention period for VPC Flow Logs in days"
  type        = number
  default     = 30

  validation {
    condition     = var.vpc_flow_logs_retention_days > 0
    error_message = "VPC Flow Logs retention must be greater than 0 days."
  }
}

# ============================================================================
# S3 Configuration Variables
# ============================================================================

variable "number_of_websites" {
  description = "Number of static websites to host"
  type        = number
  default     = 3

  validation {
    condition     = var.number_of_websites > 0 && var.number_of_websites <= 10
    error_message = "Number of websites must be between 1 and 10."
  }
}

variable "s3_enable_versioning" {
  description = "Enable S3 versioning for rollback capability"
  type        = bool
  default     = true
}

variable "s3_enable_access_logging" {
  description = "Enable S3 access logging for audit trails (SOC 2 CC6.1)"
  type        = bool
  default     = true
}

variable "s3_access_log_retention_days" {
  description = "Retention period for S3 access logs in days"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_access_log_retention_days > 0
    error_message = "S3 access log retention must be greater than 0 days."
  }
}

variable "s3_encryption_type" {
  description = "S3 encryption type: SSE-S3 or SSE-KMS (SOC 2 CC6.6, CC6.7)"
  type        = string
  default     = "SSE-S3"

  validation {
    condition     = contains(["SSE-S3", "SSE-KMS"], var.s3_encryption_type)
    error_message = "S3 encryption type must be SSE-S3 or SSE-KMS."
  }
}

variable "s3_kms_key_id" {
  description = "KMS key ID for S3 encryption (required if s3_encryption_type is SSE-KMS)"
  type        = string
  default     = null
}

variable "s3_block_public_access" {
  description = "Block all public access to S3 buckets (security best practice)"
  type        = bool
  default     = true
}

variable "s3_lifecycle_transition_days" {
  description = "Days before transitioning S3 objects to Glacier for cost optimization"
  type        = number
  default     = 180

  validation {
    condition     = var.s3_lifecycle_transition_days > 0
    error_message = "S3 lifecycle transition days must be greater than 0."
  }
}

# ============================================================================
# CloudFront Configuration Variables
# ============================================================================

variable "cloudfront_enable_logging" {
  description = "Enable CloudFront access logging for audit trails"
  type        = bool
  default     = true
}

variable "cloudfront_log_retention_days" {
  description = "Retention period for CloudFront logs in days"
  type        = number
  default     = 90

  validation {
    condition     = var.cloudfront_log_retention_days > 0
    error_message = "CloudFront log retention must be greater than 0 days."
  }
}

variable "cloudfront_price_class" {
  description = "CloudFront price class: PriceClass_All, PriceClass_100, or PriceClass_200"
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_All", "PriceClass_100", "PriceClass_200"], var.cloudfront_price_class)
    error_message = "CloudFront price class must be PriceClass_All, PriceClass_100, or PriceClass_200."
  }
}

variable "cloudfront_default_ttl" {
  description = "Default TTL for CloudFront cache in seconds"
  type        = number
  default     = 3600

  validation {
    condition     = var.cloudfront_default_ttl >= 0
    error_message = "CloudFront default TTL must be 0 or greater."
  }
}

variable "cloudfront_max_ttl" {
  description = "Maximum TTL for CloudFront cache in seconds"
  type        = number
  default     = 86400

  validation {
    condition     = var.cloudfront_max_ttl >= 0
    error_message = "CloudFront max TTL must be 0 or greater."
  }
}

variable "cloudfront_min_ttl" {
  description = "Minimum TTL for CloudFront cache in seconds"
  type        = number
  default     = 0

  validation {
    condition     = var.cloudfront_min_ttl >= 0
    error_message = "CloudFront min TTL must be 0 or greater."
  }
}

variable "cloudfront_enable_compression" {
  description = "Enable automatic compression of content by CloudFront"
  type        = bool
  default     = true
}

variable "cloudfront_viewer_protocol_policy" {
  description = "Viewer protocol policy: allow-all, https-only, or redirect-to-https"
  type        = string
  default     = "redirect-to-https"

  validation {
    condition     = contains(["allow-all", "https-only", "redirect-to-https"], var.cloudfront_viewer_protocol_policy)
    error_message = "Viewer protocol policy must be allow-all, https-only, or redirect-to-https."
  }
}

variable "cloudfront_enable_signed_urls" {
  description = "Enable CloudFront signed URLs for access control"
  type        = bool
  default     = false
}

# ============================================================================
# Route 53 Configuration Variables
# ============================================================================

variable "enable_route53" {
  description = "Enable Route 53 for custom domain management"
  type        = bool
  default     = false
}

variable "route53_zone_ids" {
  description = "Map of domain names to Route 53 hosted zone IDs"
  type        = map(string)
  default     = {}
}

variable "website_domains" {
  description = "List of custom domain names for static websites"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for domain in var.website_domains : can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$", domain))
    ])
    error_message = "All website domains must be valid domain names."
  }
}

# ============================================================================
# AWS Certificate Manager Configuration Variables
# ============================================================================

variable "acm_certificate_validation_method" {
  description = "ACM certificate validation method: DNS or EMAIL"
  type        = string
  default     = "DNS"

  validation {
    condition     = contains(["DNS", "EMAIL"], var.acm_certificate_validation_method)
    error_message = "ACM certificate validation method must be DNS or EMAIL."
  }
}

# ============================================================================
# Compliance and Security Variables
# ============================================================================

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for API audit logging (SOC 2 CC6.1)"
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention_days" {
  description = "Retention period for CloudTrail logs in days"
  type        = number
  default     = 90

  validation {
    condition     = var.cloudtrail_log_retention_days > 0
    error_message = "CloudTrail log retention must be greater than 0 days."
  }
}

variable "enable_cloudwatch_monitoring" {
  description = "Enable CloudWatch monitoring and alarms for infrastructure"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "soc2_compliance_enabled" {
  description = "Enable SOC 2 compliance controls and logging"
  type        = bool
  default     = true
}

# ============================================================================
# Website Content Configuration Variables
# ============================================================================

variable "website_index_document" {
  description = "Index document for S3 static website hosting"
  type        = string
  default     = "index.html"
}

variable "website_error_document" {
  description = "Error document for S3 static website hosting"
  type        = string
  default     = "error.html"
}

variable "website_routing_rules" {
  description = "Routing rules for S3 static website hosting"
  type        = string
  default     = ""
}

# ============================================================================
# Monitoring and Alerting Variables
# ============================================================================

variable "alert_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""

  validation {
    condition     = var.alert_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.alert_email))
    error_message = "Alert email must be a valid email address or empty string."
  }
}

variable "enable_cost_anomaly_detection" {
  description = "