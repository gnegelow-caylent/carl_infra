# AFT Account Customization for Workloads OU with SOC 2 Type II Security Services
# This module enables GuardDuty, Security Hub, and AWS Config for comprehensive security monitoring

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
      Compliance = "SOC2TypeII"
      CreatedAt  = timestamp()
      Environment = var.environment
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "workloads"
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub for security posture management"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (SOC 2 requires 7 years minimum for audit logs)"
  type        = number
  default     = 2555
}

variable "s3_log_bucket_name" {
  description = "S3 bucket for storing security logs"
  type        = string
  default     = ""
}

variable "kms_key_id" {
  description = "KMS key ID for encryption at rest"
  type        = string
  default     = ""
}

variable "config_aggregator_account_id" {
  description = "AWS Account ID for Config aggregator (if using centralized aggregation)"
  type        = string
  default     = ""
}

variable "config_aggregator_region" {
  description = "Region for Config aggregator"
  type        = string
  default     = "us-east-1"
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "security_services" {
  description             = "KMS key for SOC 2 security services encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "security-services-key"
  }
}

resource "aws_kms_alias" "security_services" {
  name          = "alias/security-services-${var.environment}"
  target_key_id = aws_kms_key.security_services.key_id
}

# S3 bucket for security logs with encryption and versioning
resource "aws_s3_bucket" "security_logs" {
  count  = var.s3_log_bucket_name == "" ? 1 : 0
  bucket = "security-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name = "security-logs-bucket"
  }
}

resource "aws_s3_bucket_versioning" "security_logs" {
  count  = var.s3_log_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  count  = var.s3_log_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security_services.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  count  = var.s3_log_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  count  = var.s3_log_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555
    }
  }
}

# CloudTrail for audit logging (SOC 2 requirement)
resource "aws_cloudtrail" "account_trail" {
  name                          = "account-audit-trail-${var.environment}"
  s3_bucket_name                = local.log_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/*"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }

  tags = {
    Name = "account-audit-trail"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = local.log_bucket_name

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
        Resource = "arn:aws:s3:::${local.log_bucket_name}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${local.log_bucket_name}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "account" {
  count            = var.enable_guardduty ? 1 : 0
  enable           = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }

  tags = {
    Name = "account-guardduty-detector"
  }
}

resource "aws_cloudwatch_log_group" "guardduty" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/guardduty/findings"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = {
    Name = "guardduty-findings-logs"
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "guardduty-findings-rule"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name = "guardduty-findings-rule"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_logs" {
  count             = var.enable_guardduty ? 1 : 0
  rule              = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id         = "GuardDutyLogsTarget"
  arn               = aws_cloudwatch_log_group.guardduty[0].arn
  role_arn          = aws_iam_role.guardduty_events.arn
}

resource "aws_iam_role" "guardduty_events" {
  name = "guardduty-events-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "guardduty-events-role"
  }
}

resource "aws_iam_role_policy" "guardduty_events" {
  name = "guardduty-events-policy"
  role = aws_iam_role.guardduty_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.guardduty[0].arn}:*"
      }
    ]
  })
}

# Security Hub for security posture management (SOC 2 requirement)
resource "aws_securityhub_account" "account" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name = "account-security-hub"
  }
}

resource "aws_securityhub_standards_subscription" "cis" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on      = [aws_securityhub_account.account]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
  depends_on      = [aws_securityhub_account.account]
}

resource "aws_cloudwatch_log_group" "security_hub" {
  count             = var.enable_security_hub ? 1 : 0
  name              = "/aws/securityhub/findings"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = {
    Name = "security-hub-findings-logs"
  }
}

# AWS Config for compliance monitoring (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "account" {
  count = var.enable_config ? 1 : 0
  name  = "account-aggregator"

  account_aggregation_sources {
    account_ids = [data.aws_caller_identity.current.account_id]
    regions     = [var.aws_region]
  }

  tags = {
    Name = "account-config-aggregator"
  }
}

resource "aws_config_configuration_recorder" "account" {
  count           = var.enable_config ? 1 : 0
  name            = "account-recorder"
  role_arn        = aws_iam_role.config_recorder[0].arn
  recording_group {
    all_supported = true
    include_global = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_policy]
}

resource "aws_config_configuration_recorder_status" "account" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.account[0].name
  is_enabled         = true
  depends_on         = [aws_config_delivery_channel.account]
  start_recording    = true
}

resource "aws_config_delivery_channel" "account" {
  count                          = var.enable_config ? 1 : 0
  name                           = "account-delivery-channel"
  s3_bucket_name                 = local.log_bucket_name
  sns_topic_arn                  = aws_sns_topic.config_notifications[0].arn
  include_global_resources       = true
  depends_on                     = [aws_config_configuration_recorder.account]

  depends_on = [aws_s3_bucket_policy.config]
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = local.log_bucket_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketVersioning"
        Resource = "arn:aws:s3:::${local.log_bucket_name}"
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::${local.log_bucket_name}"
      },
      {
        Sid    = "AWSConfigBucketPutObject"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${local.log_bucket_name}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "config_recorder" {
  count = var.enable_config ? 1 : 0
  name  = "config-recorder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "config-recorder-role"
  }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  count      = var.enable_config ? 1 : 0
  role       = aws_