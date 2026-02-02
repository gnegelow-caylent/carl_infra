# AWS Service Control Policy (SCP) for Deny Root User Actions
# SOC 2 Type II Compliance - CC6.1 (Logical and Physical Access Controls)
# Implements preventive guardrail to restrict root user actions except billing operations

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
  description = "AWS region for provider configuration"
  type        = string
  default     = "us-east-1"
}

variable "scp_name" {
  description = "Name of the Service Control Policy"
  type        = string
  default     = "deny-root-user"
}

variable "scp_description" {
  description = "Description of the SCP for audit purposes"
  type        = string
  default     = "Deny root user actions except for billing operations (SOC 2 CC6.1)"
}

variable "target_ous" {
  description = "List of Organizational Unit IDs to attach the SCP"
  type        = list(string)
  default     = []
}

variable "enable_logging" {
  description = "Enable CloudTrail logging for SCP enforcement"
  type        = bool
  default     = true
}

# Data source to get AWS Organizations
data "aws_organizations_organization" "current" {}

# Data source to get current AWS account
data "aws_caller_identity" "current" {}

# CloudWatch Log Group for SCP audit trail (7-year retention for SOC 2)
resource "aws_cloudwatch_log_group" "scp_audit_logs" {
  name              = "/aws/scp/deny-root-user"
  retention_in_days = 2555  # 7 years for SOC 2 compliance

  tags = {
    Name        = "scp-deny-root-user-audit-logs"
    Purpose     = "SCP Enforcement Audit Trail"
    Compliance  = "SOC2-TypeII"
    ManagedBy   = "CARL"
  }
}

# KMS Key for encrypting SCP audit logs (SOC 2 encryption at rest)
resource "aws_kms_key" "scp_logs_key" {
  description             = "KMS key for encrypting SCP audit logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "scp-audit-logs-key"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

resource "aws_kms_alias" "scp_logs_key_alias" {
  name          = "alias/scp-audit-logs"
  target_key_id = aws_kms_key.scp_logs_key.key_id
}

# KMS Key Policy for CloudWatch Logs
resource "aws_kms_key_policy" "scp_logs_policy" {
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
          Service = "logs.${var.aws_region}.amazonaws.com"
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
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })
}

# Service Control Policy - Deny Root User Actions
resource "aws_organizations_policy" "deny_root_user" {
  name        = var.scp_name
  description = var.scp_description
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyRootUserActions"
        Effect = "Deny"
        NotAction = [
          "aws-portal:*",
          "budgets:*",
          "ce:*",
          "cur:*",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListUsers",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      },
      {
        Sid    = "AllowBreakGlassAccess"
        Effect = "Allow"
        Action = "*"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:role/BreakGlassRole"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "deny-root-user-scp"
    Purpose     = "Preventive Control for Root User Access"
    Compliance  = "SOC2-TypeII"
    Control     = "CC6.1"
    ManagedBy   = "CARL"
  }
}

# Attach SCP to target OUs (if provided)
resource "aws_organizations_policy_attachment" "deny_root_user_attachment" {
  for_each = toset(var.target_ous)

  policy_id = aws_organizations_policy.deny_root_user.id
  target_id = each.value
}

# CloudTrail for monitoring SCP enforcement (SOC 2 logging requirement)
resource "aws_cloudtrail" "scp_enforcement_trail" {
  count = var.enable_logging ? 1 : 0

  name                          = "scp-enforcement-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_policy[0]]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::IAM::User"
      values = ["arn:aws:iam::*:root"]
    }
  }

  tags = {
    Name       = "scp-enforcement-trail"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# S3 Bucket for CloudTrail logs (encrypted, SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  count = var.enable_logging ? 1 : 0

  bucket = "scp-enforcement-trail-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name       = "scp-enforcement-trail-bucket"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# Enable versioning on CloudTrail bucket
resource "aws_s3_bucket_versioning" "cloudtrail_versioning" {
  count = var.enable_logging ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_bucket[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption on CloudTrail bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_encryption" {
  count = var.enable_logging ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.scp_logs_key.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access to CloudTrail bucket
resource "aws_s3_bucket_public_access_block" "cloudtrail_public_access_block" {
  count = var.enable_logging ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_bucket[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  count = var.enable_logging ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_bucket[0].id

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
        Resource = aws_s3_bucket.cloudtrail_bucket[0].arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket[0].arn}/*"
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
        Resource = "${aws_s3_bucket.cloudtrail_bucket[0].arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# CloudWatch Alarm for root user activity detection
resource "aws_cloudwatch_log_group" "root_activity_detection" {
  name              = "/aws/scp/root-activity-detection"
  retention_in_days = 2555  # 7 years for SOC 2

  tags = {
    Name       = "root-activity-detection"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# Metric filter for root user activity
resource "aws_cloudwatch_log_metric_filter" "root_user_activity" {
  name           = "RootUserActivityMetricFilter"
  log_group_name = aws_cloudwatch_log_group.root_activity_detection.name
  filter_pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootUserActivityCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

# SNS Topic for root user activity alerts
resource "aws_sns_topic" "root_user_alerts" {
  name              = "scp-root-user-activity-alerts"
  kms_master_key_id = aws_kms_key.scp_logs_key.id

  tags = {
    Name       = "root-user-activity-alerts"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# CloudWatch Alarm for root user activity
resource "aws_cloudwatch_metric_alarm" "root_user_activity_alarm" {
  alarm_name          = "RootUserActivityDetected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootUserActivityCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert when root user activity is detected"
  alarm_actions       = [aws_sns_topic.root_user_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name       = "root-user-activity-alarm"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# Outputs for AFT integration and reference
output "scp_id" {
  description = "The ID of the Service Control Policy"
  value       = aws_organizations_policy.deny_root_user.id
}

output "scp_arn" {
  description = "The ARN of the Service Control Policy"
  value       = aws_organizations_policy.deny_root_user.arn
}

output "scp_name" {
  description = "The name of the Service Control Policy"
  value       = aws_organizations_policy.deny_root_user.name
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = var.enable_logging ? aws_s3_bucket.cloudtrail_bucket[0].id : null
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for SCP audit logs"
  value       = aws_cloudwatch_log_group.scp_audit_logs.name
}

output "kms_key_id" {
  description = "KMS Key ID for encrypting audit logs"
  value       = aws_kms_key.scp_logs_key.id
}

output "sns_topic_arn" {
  description = "SNS Topic ARN for root user activity alerts"
  value       = aws_sns_topic.root_user_alerts.arn
}

output "compliance_controls" {
  description = "SOC 2 controls implemented by this SCP"
  value = {
    CC6_1 = "Logical and Physical Access Controls - Root User Restriction"
    CC6_6 = "Access Control - Preventive Guardrail"
    A1_2  = "Audit Trail - CloudTrail and CloudWatch Logs"
  }
}