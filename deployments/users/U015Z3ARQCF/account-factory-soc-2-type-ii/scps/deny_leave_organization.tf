# Service Control Policy (SCP) for denying organization leave
# Implements SOC 2 CC6.1 - Logical and Physical Access Controls
# Prevents accounts from leaving the AWS Organization

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data source to get the organization
data "aws_organizations_organization" "current" {}

# Service Control Policy - Deny Leave Organization
# CC6.1: Logical and Physical Access Controls
# Prevents unauthorized account removal from organization
resource "aws_organizations_policy" "deny_leave_organization" {
  name        = var.scp_name
  description = var.scp_description
  type        = "SERVICE_CONTROL_POLICY"
  content     = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyLeaveOrganization"
        Effect = "Deny"
        Action = [
          "organizations:LeaveOrganization"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name        = var.scp_name
      ManagedBy   = "CARL"
      Compliance  = "SOC2-CC6.1"
      Description = "Prevents accounts from leaving organization"
    }
  )
}

# Attach SCP to root organization if target_ous is empty
# Otherwise, attach to specified OUs
resource "aws_organizations_policy_attachment" "deny_leave_organization_root" {
  count     = length(var.target_ous) == 0 ? 1 : 0
  policy_id = aws_organizations_policy.deny_leave_organization.id
  target_id = data.aws_organizations_organization.current.roots[0].id
}

# Attach SCP to specific OUs
resource "aws_organizations_policy_attachment" "deny_leave_organization_ou" {
  for_each  = toset(var.target_ous)
  policy_id = aws_organizations_policy.deny_leave_organization.id
  target_id = each.value
}

# Variables
variable "aws_region" {
  description = "AWS region for provider"
  type        = string
  default     = "us-east-1"
}

variable "scp_name" {
  description = "Name of the Service Control Policy"
  type        = string
  default     = "deny-leave-organization"
}

variable "scp_description" {
  description = "Description of the Service Control Policy"
  type        = string
  default     = "Prevent accounts from leaving organization (CC6.1)"
}

variable "target_ous" {
  description = "List of OU IDs to attach the SCP to. If empty, attaches to root."
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "security-governance"
    CreatedBy   = "terraform"
  }
}

# Outputs
output "scp_id" {
  description = "The ID of the Service Control Policy"
  value       = aws_organizations_policy.deny_leave_organization.id
}

output "scp_arn" {
  description = "The ARN of the Service Control Policy"
  value       = aws_organizations_policy.deny_leave_organization.arn
}

output "scp_name" {
  description = "The name of the Service Control Policy"
  value       = aws_organizations_policy.deny_leave_organization.name
}

output "attached_to_root" {
  description = "Whether the SCP is attached to the organization root"
  value       = length(aws_organizations_policy_attachment.deny_leave_organization_root) > 0
}

output "attached_ous" {
  description = "List of OUs the SCP is attached to"
  value       = keys(aws_organizations_policy_attachment.deny_leave_organization_ou)
}