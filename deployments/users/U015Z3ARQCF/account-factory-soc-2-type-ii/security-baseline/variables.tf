# Security Baseline Variables

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "security_account_id" {
  description = "Security tooling account ID"
  type        = string
}

variable "primary_region" {
  description = "Primary AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "enabled_regions" {
  description = "List of regions to enable security services"
  type        = list(string)
  default     = ["us-east-1"]
}
