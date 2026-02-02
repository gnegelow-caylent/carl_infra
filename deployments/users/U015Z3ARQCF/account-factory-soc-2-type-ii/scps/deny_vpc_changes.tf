# AWS Service Control Policy (SCP) for VPC Protection
# Implements SOC 2 Type II controls CC6.6 (Logical Access Controls) and CC8.1 (Change Management)
# Prevents unauthorized deletion of critical VPC infrastructure
# Part of AFT Framework - Global Security Guardrails

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
      Purpose    = "VPC-Protection-SCP"
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
  default     = "deny_vpc_changes"
}

variable "scp_description" {
  description = "Description of the SCP purpose and compliance controls"
  type        = string
  default     = "Protect VPC infrastructure from unauthorized changes (SOC 2 CC6.6, CC8.1)"
}

variable "target_ous" {
  description = "List of Organizational Unit IDs to attach the SCP"
  type        = list(string)
  default     = []
}

variable "break_glass_roles" {
  description = "ARN patterns for break-glass roles exempt from SCP restrictions"
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/AWSControlTowerExecution",
    "arn:aws:iam::*:role/AWSAFTExecution"
  ]
}

variable "enable_logging" {
  description = "Enable CloudTrail logging for SCP policy changes"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudTrail log retention in days (SOC 2 requires 7 years minimum)"
  type        = number
  default     = 2555
}

# Data source for AWS Organizations
data "aws_organizations_organization" "current" {}

# KMS Key for CloudTrail encryption (SOC 2 encryption at rest requirement)
resource "aws_kms_key" "scp_audit_key" {
  description             = "KMS key for SCP audit trail encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "scp-audit-key"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

resource "aws_kms_alias" "scp_audit_key_alias" {
  name          = "alias/scp-audit-trail"
  target_key_id = aws_kms_key.scp_audit_key.key_id
}

# S3 bucket for CloudTrail logs (SOC 2 audit trail requirement)
resource "aws_s3_bucket" "scp_audit_logs" {
  bucket = "scp-audit-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name       = "scp-audit-logs"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# Enable versioning for audit trail integrity
resource "aws_s3_bucket_versioning" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Disabled"
  }
}

# Enable encryption at rest (SOC 2 requirement)
resource "aws_s3_bucket_server_side_encryption_configuration" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.scp_audit_key.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access (SOC 2 access control requirement)
resource "aws_s3_bucket_public_access_block" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket policy for CloudTrail access
resource "aws_s3_bucket_policy" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.scp_audit_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.scp_audit_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.scp_audit_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# Lifecycle policy for log retention (SOC 2 7-year requirement)
resource "aws_s3_bucket_lifecycle_configuration" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_retention_days
    }
  }
}

# CloudTrail for SCP policy changes (SOC 2 logging requirement)
resource "aws_cloudtrail" "scp_audit_trail" {
  count                      = var.enable_logging ? 1 : 0
  name                       = "scp-policy-audit-trail"
  s3_bucket_name             = aws_s3_bucket.scp_audit_logs.id
  include_global_events      = true
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.scp_audit_key.arn

  depends_on = [aws_s3_bucket_policy.scp_audit_logs]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::IAM::Policy"
      values = ["arn:aws:iam::*"]
    }
  }

  tags = {
    Name       = "scp-audit-trail"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Service Control Policy - Deny VPC Changes
resource "aws_organizations_policy" "deny_vpc_changes" {
  name        = var.scp_name
  description = var.scp_description
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyVPCDeletion"
        Effect = "Deny"
        Action = [
          "ec2:DeleteVpc",
          "ec2:DeleteSubnet",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteNatGateway",
          "ec2:DeleteRouteTable",
          "ec2:DeleteFlowLogs"
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = var.break_glass_roles
          }
        }
      },
      {
        Sid    = "DenyVPCModification"
        Effect = "Deny"
        Action = [
          "ec2:ModifyVpcAttribute",
          "ec2:ModifySubnetAttribute",
          "ec2:DisassociateRouteTable"
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = var.break_glass_roles
          }
        }
      }
    ]
  })

  tags = {
    Name       = var.scp_name
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
    Control    = "CC6.6-CC8.1"
  }
}

# Attach SCP to target OUs
resource "aws_organizations_policy_attachment" "deny_vpc_changes" {
  for_each = toset(var.target_ous)

  policy_id = aws_organizations_policy.deny_vpc_changes.id
  target_id = each.value
}

# CloudWatch Log Group for SCP monitoring
resource "aws_cloudwatch_log_group" "scp_monitoring" {
  name              = "/aws/scp/deny-vpc-changes"
  retention_in_days = 90

  kms_key_id = aws_kms_key.scp_audit_key.arn

  tags = {
    Name       = "scp-monitoring"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# CloudWatch Alarm for SCP policy violations
resource "aws_cloudwatch_metric_alarm" "scp_violations" {
  alarm_name          = "scp-vpc-deletion-attempts"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnauthorizedAPICallsEventCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert on SCP policy violations for VPC deletion attempts"
  treat_missing_data  = "notBreaching"

  tags = {
    Name       = "scp-violation-alarm"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# Outputs
output "scp_id" {
  description = "ID of the Service Control Policy"
  value       = aws_organizations_policy.deny_vpc_changes.id
}

output "scp_arn" {
  description = "ARN of the Service Control Policy"
  value       = aws_organizations_policy.deny_vpc_changes.arn
}

output "audit_bucket_name" {
  description = "S3 bucket name for SCP audit logs"
  value       = aws_s3_bucket.scp_audit_logs.id
}

output "audit_bucket_arn" {
  description = "S3 bucket ARN for SCP audit logs"
  value       = aws_s3_bucket.scp_audit_logs.arn
}

output "kms_key_id" {
  description = "KMS key ID for audit log encryption"
  value       = aws_kms_key.scp_audit_key.id
}

output "cloudtrail_name" {
  description = "CloudTrail name for SCP policy changes"
  value       = var.enable_logging ? aws_cloudtrail.scp_audit_trail[0].name : null
}

output "log_group_name" {
  description = "CloudWatch Log Group for SCP monitoring"
  value       = aws_cloudwatch_log_group.scp_monitoring.name
}

output "organization_id" {
  description = "AWS Organization ID"
  value       = data.aws_organizations_organization.current.id
}

output "scp_attached_ous" {
  description = "List of OUs where SCP is attached"
  value       = var.target_ous
}

output "compliance_controls" {
  description = "SOC 2 Type II controls implemented"
  value = {
    "CC6.6" = "Logical Access Controls - VPC infrastructure protection"
    "CC8.1" = "Change Management - Preventive guardrails for infrastructure changes"
    "Encryption" = "KMS encryption at rest for audit logs"
    "Audit Trail" = "7-year CloudTrail retention for compliance"
    "Monitoring" = "CloudWatch alarms for policy violations"
  }
}