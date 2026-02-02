# CloudTrail Multi-Region Organization Trail with SOC 2 Type II Compliance
# Implements comprehensive audit logging with encryption, validation, and 7-year retention

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
  alias  = "cloudtrail_bucket_region"
  region = var.cloudtrail_bucket_region
}

# Variables
variable "primary_region" {
  description = "Primary AWS region for CloudTrail"
  type        = string
  default     = "us-east-1"
}

variable "cloudtrail_bucket_region" {
  description = "AWS region for CloudTrail S3 bucket"
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

variable "retention_days" {
  description = "CloudWatch Logs retention in days (SOC 2: 7 years = 2555 days)"
  type        = number
  default     = 2555
}

variable "enable_log_file_validation" {
  description = "Enable CloudTrail log file validation (CC7.2)"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logs" {
  description = "Enable CloudTrail to CloudWatch Logs integration"
  type        = bool
  default     = true
}

variable "glacier_transition_days" {
  description = "Days before transitioning logs to Glacier for cost optimization"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default = {
    Environment = "production"
    Service     = "audit-logging"
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}

# KMS Key for CloudTrail log encryption (CC6.7)
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption - SOC 2 CC6.7"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "${var.trail_name}-key"
    }
  )
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.trail_name}-key"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# KMS Key Policy for CloudTrail
resource "aws_kms_key_policy" "cloudtrail" {
  key_id = aws_kms_key.cloudtrail.id

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
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
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
}

# S3 Bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  provider = aws.cloudtrail_bucket_region
  bucket   = "${var.trail_name}-logs-${data.aws_caller_identity.current.account_id}-${var.cloudtrail_bucket_region}"

  tags = merge(
    var.tags,
    {
      Name = "${var.trail_name}-logs"
    }
  )
}

# Block public access to CloudTrail bucket
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  provider = aws.cloudtrail_bucket_region
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning on CloudTrail bucket
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  provider = aws.cloudtrail_bucket_region
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption on CloudTrail bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  provider = aws.cloudtrail_bucket_region
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  provider = aws.cloudtrail_bucket_region
  bucket   = aws_s3_bucket.cloudtrail_logs.id

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

# S3 Lifecycle policy for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  provider = aws.cloudtrail_bucket_region
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      noncurrent_days = var.glacier_transition_days
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }
  }

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = var.retention_days
    }
  }
}

# CloudWatch Logs Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudwatch_logs ? 1 : 0
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.retention_days

  kms_key_id = "${aws_kms_key.cloudtrail.arn}:*"

  tags = merge(
    var.tags,
    {
      Name = "${var.trail_name}-logs"
    }
  )
}

# IAM Role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "${var.trail_name}-cloudwatch-logs-role"

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

  tags = var.tags
}

# IAM Policy for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "${var.trail_name}-cloudwatch-logs-policy"
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

# CloudTrail Organization Trail (Multi-Region)
resource "aws_cloudtrail" "organization" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = var.enable_log_file_validation
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]

  # CloudWatch Logs integration
  dynamic "cloud_watch_logs_group_arn" {
    for_each = var.enable_cloudwatch_logs ? [1] : []
    content {
      cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
    }
  }

  dynamic "cloud_watch_logs_role_arn" {
    for_each = var.enable_cloudwatch_logs ? [1] : []
    content {
      cloud_watch_logs_role_arn = "${aws_iam_role.cloudtrail_cloudwatch_logs[0].arn}:*"
    }
  }

  # Event selectors for comprehensive logging
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

  # Insights selector for anomaly detection
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  tags = merge(
    var.tags,
    {
      Name = var.trail_name
    }
  )
}

# CloudWatch Alarm for CloudTrail API calls
resource "aws_cloudwatch_metric_alarm" "cloudtrail_api_calls" {
  count           = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name      = "${var.trail_name}-high-api-activity"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailEventCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Alert when CloudTrail detects high API activity"
  treat_missing_data  = "notBreaching"

  tags = var.tags
}

# Outputs
output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.organization.arn
}

output "cloudtrail_home_region" {
  description = "Home region of the CloudTrail trail"
  value       = aws_cloudtrail.organization.home_region
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "kms_key_id" {
  description = "ID of the KMS key used for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Logs group for CloudTrail"
  value       = var.enable_cloudwatch_logs ? aws_cloudwatch_log_group.cloudtrail[0].name : null
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Logs group for CloudTrail"
  value       = var.enable_cloudwatch_logs ? aws_cloudwatch_log_group.cloudtrail[0].arn : null
}

output "cloudtrail_is_organization_trail" {
  description =