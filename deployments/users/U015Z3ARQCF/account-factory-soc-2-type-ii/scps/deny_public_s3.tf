# AWS Service Control Policy (SCP) for Denying Public S3 Bucket Configuration
# Implements SOC 2 Type II CC6.1 - Logical and Physical Access Controls
# Prevents unauthorized public access to S3 buckets through preventive guardrails

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

# Variables for SCP Configuration
variable "aws_region" {
  description = "AWS region for SCP deployment"
  type        = string
  default     = "us-east-1"
}

variable "scp_name" {
  description = "Name of the Service Control Policy"
  type        = string
  default     = "deny_public_s3"
}

variable "scp_description" {
  description = "Description of the SCP purpose and compliance mapping"
  type        = string
  default     = "Deny public S3 bucket configuration changes (SOC 2 CC6.1)"
}

variable "target_ou_ids" {
  description = "List of Organizational Unit IDs to attach the SCP"
  type        = list(string)
  default     = []
}

variable "enable_scp" {
  description = "Enable or disable the SCP attachment"
  type        = bool
  default     = true
}

variable "environment" {
  description = "Environment name for resource identification"
  type        = string
  default     = "production"
}

# Data source to get the organization
data "aws_organizations_organization" "current" {}

# Data source to get the root OU
data "aws_organizations_organization_root" "root" {}

# SCP Policy Document - Deny Public S3 Bucket Configuration
# Implements preventive control for CC6.1 (Logical Access Controls)
locals {
  scp_policy_document = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyPublicS3BucketConfiguration"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:DeletePublicAccessBlock",
          "s3:PutBucketAcl",
          "s3:PutObjectAcl",
          "s3:PutBucketPolicy"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
          }
        }
      },
      {
        Sid    = "DenyS3PublicAccessBlockRemoval"
        Effect = "Deny"
        Action = [
          "s3:DeletePublicAccessBlock"
        ]
        Resource = "*"
        Principal = "*"
      },
      {
        Sid    = "AllowCloudTrailS3Operations"
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:ListBucket",
          "s3:GetObject"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalService" = "cloudtrail.amazonaws.com"
          }
        }
      }
    ]
  }
}

# Create the Service Control Policy
resource "aws_organizations_policy" "deny_public_s3" {
  name            = var.scp_name
  description     = var.scp_description
  type            = "SERVICE_CONTROL_POLICY"
  content         = jsonencode(local.scp_policy_document)
  skip_destroy    = false

  tags = {
    Name        = var.scp_name
    Description = var.scp_description
    Compliance  = "SOC2-TypeII-CC6.1"
    ManagedBy   = "CARL"
    Environment = var.environment
  }
}

# Attach SCP to specified OUs
resource "aws_organizations_policy_attachment" "deny_public_s3_ou" {
  for_each = toset(var.target_ou_ids)

  policy_id = aws_organizations_policy.deny_public_s3.id
  target_id = each.value

  depends_on = [aws_organizations_policy.deny_public_s3]
}

# Attach SCP to Organization Root for global enforcement (if no specific OUs)
resource "aws_organizations_policy_attachment" "deny_public_s3_root" {
  count = length(var.target_ou_ids) == 0 ? 1 : 0

  policy_id = aws_organizations_policy.deny_public_s3.id
  target_id = data.aws_organizations_organization_root.root.id

  depends_on = [aws_organizations_policy.deny_public_s3]
}

# CloudWatch Log Group for SCP audit trail (7-year retention for SOC 2)
resource "aws_cloudwatch_log_group" "scp_audit_logs" {
  name              = "/aws/organizations/scp/${var.scp_name}"
  retention_in_days = 2555  # 7 years for SOC 2 compliance

  kms_key_id = aws_kms_key.scp_logs_key.arn

  tags = {
    Name       = "${var.scp_name}-audit-logs"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# KMS Key for encrypting SCP audit logs (SOC 2 encryption at rest)
resource "aws_kms_key" "scp_logs_key" {
  description             = "KMS key for encrypting SCP audit logs - ${var.scp_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "${var.scp_name}-logs-key"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

resource "aws_kms_alias" "scp_logs_key_alias" {
  name          = "alias/${var.scp_name}-logs"
  target_key_id = aws_kms_key.scp_logs_key.key_id
}

# KMS Key Policy for CloudTrail and CloudWatch Logs
resource "aws_kms_key_policy" "scp_logs_key_policy" {
  key_id = aws_kms_key.scp_logs_key.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:DecryptDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Outputs for AFT integration and reference
output "scp_id" {
  description = "The ID of the created Service Control Policy"
  value       = aws_organizations_policy.deny_public_s3.id
}

output "scp_arn" {
  description = "The ARN of the created Service Control Policy"
  value       = aws_organizations_policy.deny_public_s3.arn
}

output "scp_name" {
  description = "The name of the created Service Control Policy"
  value       = aws_organizations_policy.deny_public_s3.name
}

output "scp_content" {
  description = "The policy document content"
  value       = local.scp_policy_document
  sensitive   = false
}

output "attached_ou_ids" {
  description = "List of OUs where the SCP is attached"
  value       = var.target_ou_ids
}

output "audit_log_group_name" {
  description = "CloudWatch Log Group for SCP audit trail"
  value       = aws_cloudwatch_log_group.scp_audit_logs.name
}

output "kms_key_id" {
  description = "KMS Key ID for audit log encryption"
  value       = aws_kms_key.scp_logs_key.id
}

output "compliance_mapping" {
  description = "SOC 2 Type II compliance control mapping"
  value = {
    control_id  = "CC6.1"
    description = "Logical and Physical Access Controls"
    requirement = "Deny public S3 bucket configuration changes"
    framework   = "SOC2-TypeII"
  }
}