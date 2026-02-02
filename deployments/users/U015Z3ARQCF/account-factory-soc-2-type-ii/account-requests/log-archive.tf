# AFT Account Request for Log Archive Account with SOC 2 Compliance
# This module creates a new AWS account via AWS Control Tower Account Factory for Terraform (AFT)
# Purpose: Centralized CloudTrail, Config logs, VPC Flow Logs (immutable) with SOC 2 Type II compliance

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
      CreatedBy  = "Terraform"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for account request configuration
variable "aws_region" {
  description = "AWS region for account creation"
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Name of the AWS account to be created"
  type        = string
  default     = "log-archive"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test2@test.com"
}

variable "managed_organizational_unit" {
  description = "The target OU for the account"
  type        = string
  default     = "Security"
}

variable "sso_user_email" {
  description = "Email for SSO user (optional)"
  type        = string
  default     = ""
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub for compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for configuration compliance"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudTrail and Config logs retention in days (SOC 2 requires 7 years)"
  type        = number
  default     = 2555
}

variable "account_tags" {
  description = "Tags to apply to the account"
  type        = map(string)
  default = {
    OU         = "Security"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

# Data source to get current AWS account (Control Tower management account)
data "aws_caller_identity" "current" {}

data "aws_organization" "org" {}

# AFT Account Request Module
# This creates the account request that Control Tower will process
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email != "" ? var.sso_user_email : var.account_email
  }

  account_tags = merge(
    var.account_tags,
    {
      Purpose                = "Centralized CloudTrail, Config logs, VPC Flow Logs (immutable)"
      LogRetentionDays       = tostring(var.log_retention_days)
      GuardDutyEnabled       = tostring(var.enable_guardduty)
      SecurityHubEnabled     = tostring(var.enable_security_hub)
      ConfigEnabled          = tostring(var.enable_config)
      EncryptionAtRest       = "KMS"
      EncryptionInTransit    = "TLS1.2+"
      AuditTrailEnabled      = "true"
      ComplianceFramework    = "SOC2TypeII"
    }
  )

  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "SOC 2 Type II Compliance - Centralized Logging Account"
  }

  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
    log_retention_days  = var.log_retention_days
    compliance_framework = "SOC2TypeII"
  }

  account_customizations_name = "security"
}

# Outputs for account request
output "account_request_id" {
  description = "The ID of the account request"
  value       = module.aft_account_request.account_request_id
}

output "account_id" {
  description = "The AWS Account ID of the created account"
  value       = module.aft_account_request.account_id
}

output "account_arn" {
  description = "The ARN of the created account"
  value       = module.aft_account_request.account_arn
}

output "account_name" {
  description = "The name of the created account"
  value       = var.account_name
}

output "account_email" {
  description = "The email of the created account"
  value       = var.account_email
}

output "organizational_unit" {
  description = "The target organizational unit"
  value       = var.managed_organizational_unit
}

output "customization_name" {
  description = "The customization template applied to this account"
  value       = "security"
}

output "compliance_framework" {
  description = "Compliance framework applied to this account"
  value       = "SOC2TypeII"
}

output "log_retention_days" {
  description = "Log retention period in days"
  value       = var.log_retention_days
}

output "security_services_enabled" {
  description = "Security services enabled for this account"
  value = {
    guardduty    = var.enable_guardduty
    security_hub = var.enable_security_hub
    config       = var.enable_config
  }
}