# AFT Account Request Module for Development Environment
# Provisions a new AWS account via AWS Control Tower with SOC 2 compliance controls
# Integrates with AWS Account Factory for Terraform (AFT) framework

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
  description = "AWS region for account operations"
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Name of the AWS account to be created"
  type        = string
  default     = "dev"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test3@test.com"
}

variable "managed_organizational_unit" {
  description = "The target OU for the account"
  type        = string
  default     = "Workloads"
}

variable "sso_user_email" {
  description = "Email for SSO user assignment (optional)"
  type        = string
  default     = ""
}

variable "account_purpose" {
  description = "Purpose of the account"
  type        = string
  default     = "Development environment"
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
  description = "Enable AWS Config for resource compliance tracking"
  type        = bool
  default     = true
}

variable "account_tags" {
  description = "Tags to apply to the account"
  type        = map(string)
  default = {
    OU         = "Workloads"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

variable "aft_management_account_id" {
  description = "AFT management account ID"
  type        = string
}

variable "aft_log_archive_account_id" {
  description = "AFT log archive account ID"
  type        = string
}

variable "aft_audit_account_id" {
  description = "AFT audit account ID"
  type        = string
}

# Data source for Control Tower management account
data "aws_caller_identity" "current" {}

# AFT Account Request Module
# This module integrates with AWS Control Tower to provision the new account
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  # Control Tower account parameters
  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email != "" ? var.sso_user_email : var.account_email
  }

  # Account tags for metadata and compliance tracking
  account_tags = merge(
    var.account_tags,
    {
      Purpose        = var.account_purpose
      Environment    = "Development"
      Compliance     = "SOC2-TypeII"
      ManagedBy      = "CARL-AccountFactory"
      LogRetention   = "2555" # 7 years in days for SOC 2
      EncryptionType = "KMS"
    }
  )

  # Change management parameters for audit trail
  change_management_parameters = {
    change_requested_by = "Terraform-AFT"
    change_reason       = "Account provisioning for ${var.account_purpose}"
  }

  # Custom fields to trigger security service enablement
  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
    soc2_compliance     = true
    encryption_enabled  = true
  }

  # Select customization based on OU
  account_customizations_name = var.managed_organizational_unit == "Workloads" ? "workloads" : "default"
}

# Outputs for account request
output "account_id" {
  description = "The ID of the newly created AWS account"
  value       = try(module.aft_account_request.account_id, "")
}

output "account_arn" {
  description = "The ARN of the newly created AWS account"
  value       = try(module.aft_account_request.account_arn, "")
}

output "account_name" {
  description = "The name of the newly created AWS account"
  value       = var.account_name
}

output "account_email" {
  description = "The email address of the newly created AWS account"
  value       = var.account_email
}

output "organizational_unit" {
  description = "The organizational unit where the account was created"
  value       = var.managed_organizational_unit
}

output "account_tags" {
  description = "Tags applied to the account"
  value       = module.aft_account_request.account_tags
}

output "customization_name" {
  description = "The customization template applied to the account"
  value       = var.managed_organizational_unit == "Workloads" ? "workloads" : "default"
}

output "security_services_enabled" {
  description = "Security services enabled on the account"
  value = {
    guardduty    = var.enable_guardduty
    security_hub = var.enable_security_hub
    config       = var.enable_config
  }
}

output "soc2_compliance_enabled" {
  description = "SOC 2 compliance controls enabled"
  value = {
    encryption_at_rest  = true
    encryption_in_transit = true
    logging_enabled     = true
    audit_trail_enabled = true
    log_retention_days  = 2555
  }
}