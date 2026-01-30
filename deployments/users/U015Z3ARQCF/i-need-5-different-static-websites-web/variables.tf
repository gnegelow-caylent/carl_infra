```hcl
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ============================================================================
# GENERAL CONFIGURATION
# ============================================================================

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "resource_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "web"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric and hyphens, max 20 characters."
  }
}

variable "project_name" {
  description = "Project name for tagging and identification"
  type        = string
  default     = "static-websites"
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

# ============================================================================
# WEBSITE CONFIGURATION
# ============================================================================

variable "websites" {
  description = "Configuration for each static website"
  type = map(object({
    domain_name           = string
    index_document        = optional(string, "index.html")
    error_document        = optional(string, "error.html")
    enable_waf            = optional(bool, false)
    enable_access_logging = optional(bool, true)
  }))

  default = {
    website1 = {
      domain_name = "website1.example.com"
    }
    website2 = {
      domain_name = "website2.example.com"
    }
    website3 = {
      domain_name = "website3.example.com"
    }
    website4 = {
      domain_name = "website4.example.com"
    }
    website5 = {
      domain_name = "website5.example.com"
    }
  }

  validation {
    condition     = length(var.websites) == 5
    error_message = "Exactly 5 websites must be configured."
  }
}

# ============================================================================
# S3 BUCKET CONFIGURATION
# ============================================================================

variable "s3_versioning_enabled" {
  description = "Enable S3 bucket versioning for all websites"
  type        = bool
  default     = true
}

variable "s3_mfa_delete_enabled" {
  description = "Enable MFA delete protection (requires root account MFA)"
  type        = bool
  default     = false
}

variable "s3_lifecycle_days_to_ia" {
  description = "Days before transitioning objects to Infrequent Access storage class"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_lifecycle_days_to_ia >= 30
    error_message = "Minimum days for IA transition is 30."
  }
}

variable "s3_lifecycle_days_to_glacier" {
  description = "Days before transitioning objects to Glacier storage class"
  type        = number
  default     = 180

  validation {
    condition     = var.s3_lifecycle_days_to_glacier >= 90
    error_message = "Minimum days for Glacier transition is 90."
  }
}

variable "s3_lifecycle_days_to_expiration" {
  description = "Days before expiring old object versions"
  type        = number
  default     = 365

  validation {
    condition     = var.s3_lifecycle_days_to_expiration >= 180
    error_message = "Minimum days for expiration is 180."
  }
}

# ============================================================================
# CLOUDFRONT CONFIGURATION
# ============================================================================

variable "cloudfront_price_class" {
  description = "CloudFront price class (PriceClass_All, PriceClass_100, PriceClass_200)"
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_All", "PriceClass_100", "PriceClass_200"], var.cloudfront_price_class)
    error_message = "Price class must be PriceClass_All, PriceClass_100, or PriceClass_200."
  }
}

variable "cloudfront_default_ttl" {
  description = "Default TTL for CloudFront cache in seconds"
  type        = number
  default     = 3600

  validation {
    condition     = var.cloudfront_default_ttl >= 0 && var.cloudfront_default_ttl <= 31536000
    error_message = "TTL must be between 0 and 31536000 seconds."
  }
}

variable "cloudfront_max_ttl" {
  description = "Maximum TTL for CloudFront cache in seconds"
  type        = number
  default     = 86400

  validation {
    condition     = var.cloudfront_max_ttl >= 0 && var.cloudfront_max_ttl <= 31536000
    error_message = "Max TTL must be between 0 and 31536000 seconds."
  }
}

variable "cloudfront_min_ttl" {
  description = "Minimum TTL for CloudFront cache in seconds"
  type        = number
  default     = 0

  validation {
    condition     = var.cloudfront_min_ttl >= 0 && var.cloudfront_min_ttl <= 31536000
    error_message = "Min TTL must be between 0 and 31536000 seconds."
  }
}

variable "cloudfront_enable_ipv6" {
  description = "Enable IPv6 for CloudFront distributions"
  type        = bool
  default     = true
}

# ============================================================================
# ENCRYPTION & SECURITY CONFIGURATION
# ============================================================================

variable "kms_key_rotation_enabled" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_logging" {
  description = "Enable CloudTrail logging for API calls"
  type        = bool
  default     = true
}

variable "enable_s3_access_logging" {
  description = "Enable S3 server access logging"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for monitoring"
  type        = bool
  default     = true
}

# ============================================================================
# MONITORING & ALERTING CONFIGURATION
# ============================================================================

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_log_retention_days)
    error_message = "Log retention must be a valid CloudWatch value."
  }
}

variable "alarm_sns_email" {
  description = "Email address for CloudWatch alarm notifications (TODO: Set this value)"
  type        = string
  default     = ""
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

# ============================================================================
# TAGGING CONFIGURATION
# ============================================================================

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    CostCenter  = "engineering"
    Compliance  = "SOC2"
    DataClass   = "public"
  }
}

# ============================================================================
# BACKUP & DISASTER RECOVERY CONFIGURATION
# ============================================================================

variable "enable_cross_region_replication" {
  description = "Enable cross-region replication for S3 buckets"
  type        = bool
  default     = false
}

variable "replication_destination_region" {
  description = "Destination region for cross-region replication"
  type        = string
  default     = "us-west-2"
}

variable "enable_bucket_inventory" {
  description = "Enable S3 bucket inventory reports"
  type        = bool
  default     = true
}

# ============================================================================
# COMPLIANCE & GOVERNANCE CONFIGURATION
# ============================================================================

variable "enforce_ssl_only" {
  description = "Enforce SSL/TLS for all S3 bucket access"
  type        = bool
  default     = true
}

variable "block_public_access" {
  description = "Block all public access to S3 buckets"
  type        = bool
  default     = true
}

variable "enable_bucket_key_enabled" {
  description = "Enable S3 Bucket Key for KMS encryption (reduces costs)"
  type        = bool
  default     = true
}
```