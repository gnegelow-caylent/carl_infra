# Logging Module Variables

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log Archive account ID"
  type        = string
}

variable "primary_region" {
  description = "Primary AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "cloudtrail_retention_days" {
  description = "CloudTrail log retention in days"
  type        = number
  default     = 2555  # 7 years for compliance
}
