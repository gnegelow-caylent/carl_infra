# AFT Account Customization - Security Services for SOC 2 Type II Compliance
# This module enables and configures AWS security services (GuardDuty, Security Hub, Config)
# for accounts in the Security OU with comprehensive logging and monitoring

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy  = "CARL"
      Compliance = "SOC2-TypeII"
      CreatedBy  = "Terraform"
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
  default     = "production"
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
  description = "S3 bucket name for centralized logging"
  type        = string
  default     = ""
}

variable "kms_key_id" {
  description = "KMS key ID for encryption at rest"
  type        = string
  default     = ""
}

variable "organization_id" {
  description = "AWS Organization ID for delegated admin setup"
  type        = string
  default     = ""
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encryption at rest (if not provided)
resource "aws_kms_key" "security_services" {
  count                   = var.kms_key_id == "" ? 1 : 0
  description             = "KMS key for security services encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "security-services-key"
  }
}

resource "aws_kms_alias" "security_services" {
  count         = var.kms_key_id == "" ? 1 : 0
  name          = "alias/security-services"
  target_key_id = aws_kms_key.security_services[0].key_id
}

locals {
  kms_key_id = var.kms_key_id != "" ? var.kms_key_id : try(aws_kms_key.security_services[0].id, "")
}

# S3 bucket for security service logs with encryption and versioning
resource "aws_s3_bucket" "security_logs" {
  count  = var.s3_log_bucket_name == "" ? 1 : 0
  bucket = "security-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name = "security-logs"
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
      kms_master_key_id = local.kms_key_id
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

locals {
  s3_log_bucket = var.s3_log_bucket_name != "" ? var.s3_log_bucket_name : try(aws_s3_bucket.security_logs[0].id, "")
}

# CloudWatch Log Group for security services
resource "aws_cloudwatch_log_group" "security_services" {
  name              = "/aws/security-services/account-customization"
  retention_in_days = var.log_retention_days
  kms_key_arn       = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:key/${local.kms_key_id}"

  tags = {
    Name = "security-services-logs"
  }
}

# IAM Role for security services
resource "aws_iam_role" "security_services" {
  name = "security-services-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "config.amazonaws.com",
            "guardduty.amazonaws.com",
            "securityhub.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = {
    Name = "security-services-role"
  }
}

# IAM Policy for security services
resource "aws_iam_role_policy" "security_services" {
  name = "security-services-policy"
  role = aws_iam_role.security_services.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3LogsAccess"
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:s3:::${local.s3_log_bucket}",
          "arn:aws:s3:::${local.s3_log_bucket}/*"
        ]
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:key/${local.kms_key_id}"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.security_services.arn}:*"
      }
    ]
  })
}

# GuardDuty Detector for threat detection
resource "aws_guardduty_detector" "main" {
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
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes = true
      }
    }
  }

  tags = {
    Name = "guardduty-detector"
  }
}

# CloudWatch Log Group for GuardDuty findings
resource "aws_cloudwatch_log_group" "guardduty_findings" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/guardduty/findings"
  retention_in_days = var.log_retention_days
  kms_key_arn       = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:key/${local.kms_key_id}"

  tags = {
    Name = "guardduty-findings-logs"
  }
}

# EventBridge rule for GuardDuty findings
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

resource "aws_cloudwatch_event_target" "guardduty_findings_logs" {
  count             = var.enable_guardduty ? 1 : 0
  rule              = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id         = "GuardDutyFindingsToLogs"
  arn               = aws_cloudwatch_log_group.guardduty_findings[0].arn
  role_arn          = aws_iam_role.eventbridge.arn
  log_group_name    = aws_cloudwatch_log_group.guardduty_findings[0].name
}

# AWS Config for compliance monitoring
resource "aws_config_configuration_aggregator" "organization" {
  count = var.enable_config ? 1 : 0
  name  = "organization-aggregator"

  account_aggregation_sources {
    all_regions = true
  }

  tags = {
    Name = "organization-aggregator"
  }
}

resource "aws_config_configuration_recorder" "main" {
  count       = var.enable_config ? 1 : 0
  name        = "default"
  role_arn    = aws_iam_role.config_recorder[0].arn
  depends_on  = [aws_iam_role_policy_attachment.config_recorder]

  recording_group {
    all_supported = true
    include_global = true

    recording_strategy {
      use_only = "CONFIG_RECORDER"
    }
  }

  tags = {
    Name = "config-recorder"
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.main[0].name
  is_enabled         = true
  depends_on         = [aws_config_delivery_channel.main]
  start_recording    = true
}

resource "aws_config_delivery_channel" "main" {
  count                          = var.enable_config ? 1 : 0
  name                           = "default"
  s3_bucket_name                 = local.s3_log_bucket
  sns_topic_arn                  = aws_sns_topic.config_notifications[0].arn
  depends_on                     = [aws_config_configuration_recorder.main]

  s3_key_prefix = "config"

  recording_frequency = "CONTINUOUS"

  tags = {
    Name = "config-delivery-channel"
  }
}

# IAM Role for Config Recorder
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

resource "aws_iam_role_policy_attachment" "config_recorder" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config_recorder[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_config ? 1 : 0
  name  = "config-s3-policy"
  role  = aws_iam_role.config_recorder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:s3:::${local.s3_log_bucket}",
          "arn:aws:s3:::${local.s3_log_bucket}/*"
        ]
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:key/${local.kms_key_id}"
      }
    ]
  })
}

# SNS Topic for Config notifications
resource "aws_sns_topic" "config_notifications" {
  count             = var.enable_config ? 1 : 0
  name              = "config-notifications"
  kms_master_key_id = local.kms_key_id

  tags = {
    Name = "config-notifications"
  }
}

resource "aws_sns_topic_policy" "config_notifications" {
  count  = var.enable_config ? 1 : 0
  arn    = aws_sns_topic.config_notifications[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConfigPublish"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.config_notifications[0].arn
      }
    ]
  })
}

# Security Hub for security posture management
resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0
  tags = {
    Name = "security-hub"
  }
}

resource "aws_