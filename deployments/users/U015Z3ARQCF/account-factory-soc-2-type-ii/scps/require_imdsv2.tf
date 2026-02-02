# AWS Service Control Policy (SCP) for IMDSv2 Requirement
# Implements SOC 2 CC6.1 - Logical and Physical Access Controls
# Prevents EC2 instances from being launched without IMDSv2 enabled
# Part of AFT Framework - SCPs directory

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
  default     = "require-imdsv2"
}

variable "scp_description" {
  description = "Description of the SCP for audit purposes"
  type        = string
  default     = "Require IMDSv2 for EC2 instances (SOC 2 CC6.1)"
}

variable "target_ou_ids" {
  description = "List of Organizational Unit IDs to attach the SCP to"
  type        = list(string)
  default     = []
}

variable "enable_scp" {
  description = "Enable or disable the SCP attachment"
  type        = bool
  default     = true
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = "production"
}

# Data source to get the organization
data "aws_organizations_organization" "current" {}

# IMDSv2 Requirement SCP - Preventive Control for CC6.1
# Denies EC2:RunInstances unless MetadataHttpTokens is set to "required"
resource "aws_organizations_policy" "require_imdsv2" {
  name        = var.scp_name
  description = var.scp_description
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyEC2RunInstancesWithoutIMDSv2"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      },
      {
        Sid    = "DenyEC2RunInstancesWithoutIMDSv2OnVolume"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      }
    ]
  })

  tags = {
    Name        = var.scp_name
    Description = var.scp_description
    Environment = var.environment
    SOC2Control = "CC6.1"
    PolicyType  = "Preventive"
  }
}

# Attach SCP to target OUs
resource "aws_organizations_policy_attachment" "require_imdsv2_attachment" {
  for_each = toset(var.target_ou_ids)

  policy_id = aws_organizations_policy.require_imdsv2.id
  target_id = each.value
}

# Outputs for AFT integration and audit trail
output "scp_id" {
  description = "The ID of the IMDSv2 requirement SCP"
  value       = aws_organizations_policy.require_imdsv2.id
}

output "scp_arn" {
  description = "The ARN of the IMDSv2 requirement SCP"
  value       = aws_organizations_policy.require_imdsv2.arn
}

output "scp_name" {
  description = "The name of the IMDSv2 requirement SCP"
  value       = aws_organizations_policy.require_imdsv2.name
}

output "attached_ou_ids" {
  description = "List of OUs where the SCP is attached"
  value       = var.target_ou_ids
}

output "organization_id" {
  description = "The AWS Organization ID"
  value       = data.aws_organizations_organization.current.id
}

output "scp_policy_content" {
  description = "The policy document content for audit trail"
  value       = aws_organizations_policy.require_imdsv2.content
  sensitive   = false
}

output "compliance_framework" {
  description = "Compliance framework and control mapping"
  value = {
    framework = "SOC 2 Type II"
    control   = "CC6.1"
    objective = "Logical and Physical Access Controls"
    requirement = "Enforce IMDSv2 for EC2 metadata service access"
  }
}