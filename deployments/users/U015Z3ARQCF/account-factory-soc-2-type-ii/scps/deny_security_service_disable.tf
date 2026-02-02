# AWS Service Control Policy (SCP) for Denying Security Service Disablement
# Implements SOC 2 Type II controls CC7.1 (Logical and Physical Access Controls)
# and CC7.2 (Prior to Issuing System Credentials)
# Prevents unauthorized disabling of critical security services

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
      ManagedBy  = "CARL"
      Compliance = "SOC2-TypeII"
      Framework  = "AFT"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for SCP configuration
variable "aws_region" {
  description = "AWS region for provider"
  type        = string
  default     = "us-east-1"
}

variable "scp_name" {
  description = "Name of the Service Control Policy"
  type        = string
  default     = "deny-security-service-disable"
}

variable "scp_description" {
  description = "Description of the SCP for SOC 2 compliance"
  type        = string
  default     = "Prevent disabling security services (CC7.1, CC7.2) - SOC 2 Type II"
}

variable "target_ous" {
  description = "List of Organizational Unit IDs to attach the SCP"
  type        = list(string)
  default     = []
}

variable "enable_break_glass_exception" {
  description = "Enable break-glass exception for emergency access"
  type        = bool
  default     = true
}

variable "break_glass_principal_arn" {
  description = "ARN of principal allowed break-glass access (e.g., emergency admin role)"
  type        = string
  default     = ""
}

# Data source to get the organization
data "aws_organizations_organization" "current" {}

# Data source to get the root OU
data "aws_organizations_organizational_unit" "root" {
  parent_id = data.aws_organizations_organization.current.roots[0].id
  name      = "Root"
}

# SCP Policy Document - Deny security service disablement
# Implements preventive controls for SOC 2 CC7.1 and CC7.2
locals {
  scp_policy_document = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenySecurityServiceDisable"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:UpdateDetector",
          "securityhub:DisableSecurityHub",
          "securityhub:DeleteMembers",
          "securityhub:DisassociateFromMasterAccount",
          "config:DeleteConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "access-analyzer:DeleteAnalyzer",
          "macie2:DisableMacie",
          "inspector2:Disable"
        ]
        Resource = "*"
        Condition = var.enable_break_glass_exception && var.break_glass_principal_arn != "" ? {
          StringNotLike = {
            "aws:PrincipalArn" = [var.break_glass_principal_arn]
          }
        } : null
      }
    ]
  }

  # Remove null conditions
  scp_policy_statement = [
    for stmt in local.scp_policy_document.Statement :
    merge(
      stmt,
      stmt.Condition == null ? {} : { Condition = stmt.Condition }
    )
  ]

  scp_policy_final = {
    Version   = local.scp_policy_document.Version
    Statement = local.scp_policy_statement
  }
}

# Create the Service Control Policy
resource "aws_organizations_policy" "deny_security_service_disable" {
  name            = var.scp_name
  description     = var.scp_description
  type            = "SERVICE_CONTROL_POLICY"
  content         = jsonencode(local.scp_policy_final)
  skip_destroy    = false

  tags = {
    Name        = var.scp_name
    Description = var.scp_description
    SOC2Control = "CC7.1,CC7.2"
    Purpose     = "Preventive Control - Security Service Protection"
  }
}

# Attach SCP to specified OUs
resource "aws_organizations_policy_attachment" "deny_security_service_disable" {
  for_each = toset(var.target_ous)

  policy_id = aws_organizations_policy.deny_security_service_disable.id
  target_id = each.value
}

# Outputs for AFT integration and reference
output "scp_id" {
  description = "ID of the created Service Control Policy"
  value       = aws_organizations_policy.deny_security_service_disable.id
}

output "scp_arn" {
  description = "ARN of the created Service Control Policy"
  value       = aws_organizations_policy.deny_security_service_disable.arn
}

output "scp_name" {
  description = "Name of the created Service Control Policy"
  value       = aws_organizations_policy.deny_security_service_disable.name
}

output "policy_attachments" {
  description = "Map of OU IDs to policy attachment status"
  value = {
    for ou_id, attachment in aws_organizations_policy_attachment.deny_security_service_disable :
    ou_id => attachment.id
  }
}

output "scp_policy_document" {
  description = "The SCP policy document in JSON format"
  value       = jsonencode(local.scp_policy_final)
  sensitive   = false
}

output "soc2_controls_implemented" {
  description = "SOC 2 controls implemented by this SCP"
  value = {
    "CC7.1" = "Logical and Physical Access Controls - Preventive control for security service protection"
    "CC7.2" = "Prior to Issuing System Credentials - Prevents unauthorized modification of security configurations"
  }
}