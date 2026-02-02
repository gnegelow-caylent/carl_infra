# AWS Security Services Module - SOC 2 Type II Compliance
# Implements GuardDuty, Security Hub, AWS Config, and Inspector
# for comprehensive threat detection, configuration management, and vulnerability scanning

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

  default_tags {
    tags = {
      ManagedBy  = "CARL"
      Compliance = "SOC2-Type-II"
      Module     = "security-services"
      CreatedAt  = timestamp()
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for security services"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for centralized security findings"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for configuration recording and compliance"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable Amazon Inspector for vulnerability scanning"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Amazon Macie for S3 data classification"
  type        = bool
  default     = false
}

variable "guardduty_datasources" {
  description = "GuardDuty data sources to enable"
  type        = list(string)
  default     = ["s3_logs", "kubernetes_audit_logs", "malware_protection"]
}

variable "security_hub_standards" {
  description = "Security Hub standards to enable"
  type        = list(string)
  default     = ["CIS AWS Foundations", "AWS Foundational Security Best Practices"]
}

variable "config_all_supported" {
  description = "Enable AWS Config to record all supported resources"
  type        = bool
  default     = true
}

variable "inspector_resource_types" {
  description = "Inspector resource types to scan"
  type        = list(string)
  default     = ["EC2", "ECR", "LAMBDA"]
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (SOC 2 requires 7 years minimum for audit logs)"
  type        = number
  default     = 2555
}

variable "config_log_retention_days" {
  description = "AWS Config log retention in days"
  type        = number
  default     = 2555
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS key for encrypting security service logs and data
resource "aws_kms_key" "security_services" {
  description             = "KMS key for encrypting security services data - SOC 2 CC6.1"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "security-services-key"
    }
  )
}

resource "aws_kms_alias" "security_services" {
  name          = "alias/security-services-${var.environment}"
  target_key_id = aws_kms_key.security_services.key_id
}

# S3 bucket for security service logs with encryption and versioning
resource "aws_s3_bucket" "security_logs" {
  bucket = "security-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = merge(
    var.tags,
    {
      Name = "security-logs"
    }
  )
}

resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security_services.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

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

# CloudWatch Log Group for security services
resource "aws_cloudwatch_log_group" "security_services" {
  name              = "/aws/security-services/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = merge(
    var.tags,
    {
      Name = "security-services-logs"
    }
  )
}

# ============================================================================
# AWS GuardDuty - Threat Detection (SOC 2 CC7.1)
# ============================================================================

resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable = true

  datasources {
    s3_logs {
      enable = contains(var.guardduty_datasources, "s3_logs")
    }
    kubernetes {
      audit_logs {
        enable = contains(var.guardduty_datasources, "kubernetes_audit_logs")
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes = contains(var.guardduty_datasources, "malware_protection")
      }
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "guardduty-detector"
    }
  )
}

# GuardDuty publishing destination for findings
resource "aws_guardduty_publishing_destination" "main" {
  count = var.enable_guardduty ? 1 : 0

  detector_id             = aws_guardduty_detector.main[0].id
  destination_arn         = aws_s3_bucket.security_logs.arn
  kms_key_arn             = aws_kms_key.security_services.arn
  destination_type        = "S3"
  enable                  = true

  depends_on = [aws_s3_bucket_policy.guardduty_logs]
}

# S3 bucket policy for GuardDuty
resource "aws_s3_bucket_policy" "guardduty_logs" {
  bucket = aws_s3_bucket.security_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyPutObject"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowGuardDutyGetBucketVersioning"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetBucketVersioning"
        Resource = aws_s3_bucket.security_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ============================================================================
# AWS Security Hub - Centralized Security Findings (SOC 2 CC7.2)
# ============================================================================

resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = false

  tags = merge(
    var.tags,
    {
      Name = "security-hub"
    }
  )
}

# Enable CIS AWS Foundations standard
resource "aws_securityhub_standards_subscription" "cis_aws_foundations" {
  count = var.enable_security_hub && contains(var.security_hub_standards, "CIS AWS Foundations") ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Enable AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "aws_fsbp" {
  count = var.enable_security_hub && contains(var.security_hub_standards, "AWS Foundational Security Best Practices") ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Security Hub findings to CloudWatch Events for alerting
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  count = var.enable_security_hub ? 1 : 0

  name        = "security-hub-findings-${var.environment}"
  description = "Capture Security Hub findings for alerting"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
      }
    }
  })

  tags = merge(
    var.tags,
    {
      Name = "security-hub-findings-rule"
    }
  )
}

resource "aws_cloudwatch_event_target" "security_hub_log_group" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.security_hub_findings[0].name
  target_id = "SecurityHubFindingsLogGroup"
  arn       = aws_cloudwatch_log_group.security_services.arn
}

# ============================================================================
# AWS Config - Configuration Recording and Compliance (SOC 2 CC7.2)
# ============================================================================

# IAM role for AWS Config
resource "aws_iam_role" "config_role" {
  count = var.enable_config ? 1 : 0

  name = "aws-config-role-${var.environment}"

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

  tags = merge(
    var.tags,
    {
      Name = "aws-config-role"
    }
  )
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  count = var.enable_config ? 1 : 0

  role       = aws_iam_role.config_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  count = var.enable_config ? 1 : 0

  name = "config-s3-policy"
  role = aws_iam_role.config_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          aws_s3_bucket.security_logs.arn,
          "${aws_s3_bucket.security_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.security_services.arn
      }
    ]
  })
}

# AWS Config Recorder
resource "aws_config_configuration_recorder" "main" {
  count = var.enable_config ? 1 : 0

  name       = "config-recorder-${var.environment}"
  role_arn   = aws_iam_role.config_role[0].arn
  depends_on = [aws_iam_role_policy_attachment.config_policy]

  recording_group {
    all_supported = var.config_all_supported
    include_global = true
  }

  tags = merge(
    var.tags,
    {
      Name = "config-recorder"
    }
  )
}

resource "aws_config_configuration_recorder_status" "main" {
  count = var.enable_config ? 1 : 0

  name              = aws_config_configuration_recorder.main[0].name
  is_enabled        = true
  depends_on        = [aws_config_delivery_channel.main]
  start_recording   = true
}

# AWS Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  count = var.enable_config ? 1 : 0

  name           = "config-delivery-channel-${var.environment}"
  s3_bucket_name = aws_s3_bucket.security_logs.id
  depends_on     = [aws_iam_role_policy.config_s3_policy]

  s3_key_prefix = "config"

  sns_topic_arn = aws_sns_topic.config_notifications[0].arn

  tags = merge(
    var.tags,
    {
      Name = "config-delivery-channel"
    }
  )
}

# SNS topic for Config notifications
resource "aws_sns_topic" "config_notifications" {
  count = var.enable_config ? 1 : 0

  name              = "config-notifications-${var.environment}"
  kms_master_key_id = aws_kms_key.security_services.id

  tags = merge(
    var.tags,
    {
      Name = "config-notifications"
    }
  )
}

resource "aws_sns_topic_policy" "config_notifications" {
  count = var.enable_config ? 1 : 0

  arn = aws_sns_topic.config_notifications[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "