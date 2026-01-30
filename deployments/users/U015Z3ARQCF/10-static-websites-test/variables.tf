```hcl
# ============================================================================
# TERRAFORM VARIABLES - Static Websites with CloudFront + WAF
# ============================================================================
# This file defines all input variables for the multi-site static website
# infrastructure. All variables include validation, descriptions, and defaults.

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

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.aws_region))
    error_message = "AWS region must be a valid region format (e.g., us-east-1)."
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

variable "resource_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "test"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric with hyphens, max 20 characters."
  }
}

variable "project_name" {
  description = "Project name for tagging and identification"
  type        = string
  default     = "static-websites"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    ManagedBy = "Terraform"
    Project   = "static-websites"
  }
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
    enable_versioning     = optional(bool, true)
    enable_waf            = optional(bool, true)
    cache_ttl_default     = optional(number, 3600)
    cache_ttl_max         = optional(number, 86400)
    enable_access_logging = optional(bool, true)
  }))

  default = {
    site1 = {
      domain_name = "site1.example.com"
    }
    site2 = {
      domain_name = "site2.example.com"
    }
    site3 = {
      domain_name = "site3.example.com"
    }
    site4 = {
      domain_name = "site4.example.com"
    }
    site5 = {
      domain_name = "site5.example.com"
    }
    site6 = {
      domain_name = "site6.example.com"
    }
    site7 = {
      domain_name = "site7.example.com"
    }
    site8 = {
      domain_name = "site8.example.com"
    }
    site9 = {
      domain_name = "site9.example.com"
    }
    site10 = {
      domain_name = "site10.example.com"
    }
  }

  validation {
    condition     = length(var.websites) == 10
    error_message = "Exactly 10 websites must be configured."
  }
}

# ============================================================================
# S3 BUCKET CONFIGURATION
# ============================================================================

variable "s3_enable_versioning" {
  description = "Enable S3 versioning for rollback capability"
  type        = bool
  default     = true
}

variable "s3_enable_server_access_logging" {
  description = "Enable S3 server access logging for compliance"
  type        = bool
  default     = true
}

variable "s3_block_public_access" {
  description = "Block all public access to S3 buckets"
  type        = bool
  default     = true
}

variable "s3_lifecycle_days_to_glacier" {
  description = "Days before transitioning objects to Glacier storage class"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_lifecycle_days_to_glacier > 0
    error_message = "Days to Glacier must be greater than 0."
  }
}

variable "s3_lifecycle_days_to_expiration" {
  description = "Days before expiring old object versions"
  type        = number
  default     = 365

  validation {
    condition     = var.s3_lifecycle_days_to_expiration > var.s3_lifecycle_days_to_glacier
    error_message = "Expiration days must be greater than Glacier transition days."
  }
}

# ============================================================================
# CLOUDFRONT CONFIGURATION
# ============================================================================

variable "cloudfront_enable_ipv6" {
  description = "Enable IPv6 for CloudFront distributions"
  type        = bool
  default     = true
}

variable "cloudfront_price_class" {
  description = "CloudFront price class (PriceClass_All, PriceClass_100, PriceClass_200)"
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_All", "PriceClass_100", "PriceClass_200"], var.cloudfront_price_class)
    error_message = "Price class must be one of: PriceClass_All, PriceClass_100, PriceClass_200."
  }
}

variable "cloudfront_default_ttl" {
  description = "Default TTL for CloudFront cache in seconds"
  type        = number
  default     = 3600

  validation {
    condition     = var.cloudfront_default_ttl >= 0
    error_message = "Default TTL must be non-negative."
  }
}

variable "cloudfront_max_ttl" {
  description = "Maximum TTL for CloudFront cache in seconds"
  type        = number
  default     = 86400

  validation {
    condition     = var.cloudfront_max_ttl >= var.cloudfront_default_ttl
    error_message = "Max TTL must be greater than or equal to default TTL."
  }
}

variable "cloudfront_enable_access_logging" {
  description = "Enable CloudFront access logging for security monitoring"
  type        = bool
  default     = true
}

variable "cloudfront_http_version" {
  description = "HTTP version for CloudFront (http1.1, http2, http2and3, http3)"
  type        = string
  default     = "http2and3"

  validation {
    condition     = contains(["http1.1", "http2", "http2and3", "http3"], var.cloudfront_http_version)
    error_message = "HTTP version must be one of: http1.1, http2, http2and3, http3."
  }
}

# ============================================================================
# WAF CONFIGURATION
# ============================================================================

variable "waf_enable_rate_limiting" {
  description = "Enable WAF rate limiting rule"
  type        = bool
  default     = true
}

variable "waf_rate_limit_threshold" {
  description = "Number of requests per 5-minute period before rate limiting"
  type        = number
  default     = 2000

  validation {
    condition     = var.waf_rate_limit_threshold > 0
    error_message = "Rate limit threshold must be greater than 0."
  }
}

variable "waf_enable_geo_blocking" {
  description = "Enable WAF geo-blocking rule"
  type        = bool
  default     = false
}

variable "waf_blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2 format)"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for country in var.waf_blocked_countries : can(regex("^[A-Z]{2}$", country))])
    error_message = "Country codes must be ISO 3166-1 alpha-2 format (e.g., CN, RU)."
  }
}

variable "waf_enable_common_rule_set" {
  description = "Enable AWS Managed Rules for Common Rule Set (OWASP Top 10)"
  type        = bool
  default     = true
}

variable "waf_enable_known_bad_inputs" {
  description = "Enable AWS Managed Rules for Known Bad Inputs"
  type        = bool
  default     = true
}

variable "waf_enable_sql_injection_protection" {
  description = "Enable AWS Managed Rules for SQL Injection Protection"
  type        = bool
  default     = true
}

variable "waf_enable_xss_protection" {
  description = "Enable AWS Managed Rules for XSS Protection"
  type        = bool
  default     = true
}

# ============================================================================
# MONITORING & LOGGING CONFIGURATION
# ============================================================================

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for monitoring"
  type        = bool
  default     = true
}

variable "cloudwatch_alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications (TODO: Create SNS topic and provide ARN)"
  type        = string
  default     = ""
}

variable "cloudfront_4xx_error_threshold" {
  description = "CloudFront 4xx error rate threshold for alarm (percentage)"
  type        = number
  default     = 5

  validation {
    condition     = var.cloudfront_4xx_error_threshold > 0 && var.cloudfront_4xx_error_threshold <= 100
    error_message = "Error threshold must be between 0 and 100."
  }
}

variable "cloudfront_5xx_error_threshold" {
  description = "CloudFront 5xx error rate threshold for alarm (percentage)"
  type        = number
  default     = 1

  validation {
    condition     = var.cloudfront_5xx_error_threshold > 0 && var.cloudfront_5xx_error_threshold <= 100
    error_message = "Error threshold must be between 0 and 100."
  }
}

variable "waf_blocked_requests_threshold" {
  description = "WAF blocked requests threshold for alarm (count per 5 minutes)"
  type        = number
  default     = 100

  validation {
    condition     = var.waf_blocked_requests_threshold > 0
    error_message = "Threshold must be greater than 0."
  }
}

# ============================================================================
# KMS ENCRYPTION CONFIGURATION
# ============================================================================

variable "enable_kms_encryption" {
  description = "Enable KMS encryption for S3 and CloudFront logs"
  type        = bool
  default     = true
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days (7-30)"
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "kms_enable_key_rotation" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

# ============================================================================
# ROUTE53 CONFIGURATION (OPTIONAL)
# ============================================================================

variable "enable_route53_records" {
  description = "Enable Route53 DNS records for custom domains"
  type        = bool
  default     = false
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID (TODO: Provide if enable_route53_records is true)"
  type        = string
  default     = ""
}

# ============================================================================
# ACM CERTIFICATE CONFIGURATION
# ============================================================================

variable "acm_certificate_arn" {
  description = "ARN of existing ACM certificate for CloudFront (TODO: Create certificate or provide ARN)"
  type        = string
  default     = ""
}

variable "enable_acm_certificate_validation" {
  description = "Enable automatic ACM certificate validation"
  type        = bool
  default     = true
}
```