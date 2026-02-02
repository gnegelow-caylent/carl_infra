# CloudTrail Multi-Region Organization Trail with SOC 2 Type II Compliance
# Implements CC7.2 (audit logging), CC6.7 (encryption), and CC9.2 (access controls)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.primary_region

  default_tags {
    tags = {
      ManagedBy  = "CARL"
      Compliance = "SOC2-TypeII"
      CreatedAt  = timestamp()
    }
  }
}

provider "aws" {
  alias  = "cloudtrail_logs"
  region = var.primary_region
}

# Variables
variable "primary_region" {
  description = "Primary AWS region for CloudTrail resources"
  type        = string
  default     = "us-east-1"
}

variable "organization_id" {
  description = "AWS Organization ID for organization trail"
  type        = string
}

variable "trail_name" {
  description = "Name of the CloudTrail trail"
  type        = string
  default     = "organization-multi-region-trail"
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  type        = string
}

variable "cloudwatch_log_group_name" {
  description = "CloudWatch Logs group name for CloudTrail events"
  type        = string
  default     = "/aws/cloudtrail/organization-trail"
}

variable "log_retention_days" {
  description = "CloudTrail log retention in days (SOC 2 requires 7 years = 2555 days)"
  type        = number
  default     = 2555
}

variable "glacier_transition_days" {
  description = "Days before transitioning logs to Glacier for cost optimization"
  type        = number
  default     = 90
}

variable "enable_log_file_validation" {
  description = "Enable CloudTrail log file validation (CC7.2)"
  type        = bool
  default     = true
}

variable "include_global_service_events" {
  description = "Include global service events in trail"
  type        = bool
  default     = true
}

variable "is_multi_region_trail" {
  description = "Enable multi-region trail for complete coverage"
  type        = bool
  default     = true
}

variable "is_organization_trail" {
  description = "Enable organization trail for all member accounts"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logs" {
  description = "Enable CloudWatch Logs integration for real-time alerting"
  type        = bool
  default     = true
}

# KMS Key for CloudTrail Log Encryption (CC6.7)
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption - SOC 2 CC6.7"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:DecryptDataKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:s3:::${var.s3_bucket_name}/*"
          }
        }
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "cloudtrail-encryption-key"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloudtrail-logs"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# S3 Bucket for CloudTrail Logs with Encryption and Lifecycle
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = var.s3_bucket_name

  tags = {
    Name = "cloudtrail-logs-bucket"
  }
}

# Block public access to S3 bucket
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for audit trail integrity
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = true
  }
}

# Lifecycle policy for cost optimization (Glacier after 90 days, delete after 7 years)
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_retention_days
    }
  }
}

# Deny unencrypted uploads
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

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
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
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
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyWrongKMSKey"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.cloudtrail.arn
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# CloudWatch Logs Group for CloudTrail Events (CC7.2)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudwatch_logs ? 1 : 0
  name              = var.cloudwatch_log_group_name
  retention_in_days = var.log_retention_days

  kms_key_id = "${aws_kms_key.cloudtrail.arn}:*"

  tags = {
    Name = "cloudtrail-logs"
  }
}

# IAM Role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "cloudtrail-cloudwatch-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "cloudtrail-cloudwatch-logs-role"
  }
}

# IAM Policy for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "cloudtrail-cloudwatch-logs-policy"
  role  = aws_iam_role.cloudtrail_cloudwatch_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
      }
    ]
  })
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Multi-Region Organization CloudTrail (CC7.2, CC9.2)
resource "aws_cloudtrail" "organization" {
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch_logs
  ]

  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region_trail
  is_organization_trail         = var.is_organization_trail
  enable_log_file_validation    = var.enable_log_file_validation
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  # CloudWatch Logs integration
  cloud_watch_logs_group_arn = var.enable_cloudwatch_logs ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
  cloud_watch_logs_role_arn  = var.enable_cloudwatch_logs ? aws_iam_role.cloudtrail_cloudwatch_logs[0].arn : null

  # Event selectors for comprehensive logging (CC7.2)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }

  # Exclude KMS decrypt events to reduce noise
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true

    exclude_management_event_source {
      values = ["kms.amazonaws.com"]
    }
  }

  tags = {
    Name = var.trail_name
  }
}

# CloudWatch Alarm for CloudTrail API calls (CC7.2)
resource "aws_cloudwatch_log_group" "cloudtrail_alarms" {
  count             = var.enable_cloudwatch_logs ? 1 : 0
  name              = "/aws/cloudtrail/alarms"
  retention_in_days = var.log_retention_days

  kms_key_id = "${aws_kms_key.cloudtrail.arn}:*"

  tags = {
    Name = "cloudtrail-alarms"
  }
}

# Metric filter for unauthorized API calls
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count          = var.enable_cloudwatch_logs ? 1 : 0
  name           = "UnauthorizedAPICallsMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name
  filter_pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICallsCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

# Alarm for unauthorized API calls
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count               = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name          = "cloudtrail-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnauthorizedAPICallsCount"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert when unauthorized API calls are detected"
  treat_missing_data  = "notBreaching"
}

# Outputs
output "cloudtrail_id" {
  description = "CloudTrail ID"
  value       = aws_cloudtrail.organization.id
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.organization.arn
}

output "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "s3_bucket_arn" {
  description = "S3 bucket ARN for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "kms_