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
      Purpose    = "Security-Services"
      CreatedAt  = timestamp()
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

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "security_account_id" {
  description = "Security account ID for centralized logging"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years minimum)"
  type        = number
  default     = 2555
}

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for security posture management"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encryption at rest - SOC 2 Control: Encryption
resource "aws_kms_key" "security_services" {
  description             = "KMS key for security services encryption (GuardDuty, Config, Security Hub)"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "security-services-key"
    }
  )
}

resource "aws_kms_alias" "security_services" {
  name          = "alias/security-services-${data.aws_caller_identity.current.account_id}"
  target_key_id = aws_kms_key.security_services.key_id
}

# KMS Key Policy for security services
resource "aws_kms_key_policy" "security_services" {
  key_id = aws_kms_key.security_services.id

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
        Sid    = "Allow GuardDuty to use the key"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Config to use the key"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Security Hub to use the key"
        Effect = "Allow"
        Principal = {
          Service = "securityhub.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
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
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })
}

# S3 Bucket for Config and GuardDuty findings - SOC 2 Control: Audit Trail
resource "aws_s3_bucket" "security_findings" {
  bucket = "security-findings-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = merge(
    var.tags,
    {
      Name = "security-findings-bucket"
    }
  )
}

# Enable versioning for audit trail
resource "aws_s3_bucket_versioning" "security_findings" {
  bucket = aws_s3_bucket.security_findings.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "security_findings" {
  bucket = aws_s3_bucket.security_findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security_services.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "security_findings" {
  bucket = aws_s3_bucket.security_findings.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable logging
resource "aws_s3_bucket_logging" "security_findings" {
  bucket = aws_s3_bucket.security_findings.id

  target_bucket = aws_s3_bucket.security_findings.id
  target_prefix = "access-logs/"
}

# Bucket policy for security services
resource "aws_s3_bucket_policy" "security_findings" {
  bucket = aws_s3_bucket.security_findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_findings.arn}/*"
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
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.security_findings.arn,
          "${aws_s3_bucket.security_findings.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowGuardDutyFindings"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.security_findings.arn}/*"
      },
      {
        Sid    = "AllowConfigDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          aws_s3_bucket.security_findings.arn,
          "${aws_s3_bucket.security_findings.arn}/*"
        ]
      }
    ]
  })
}

# CloudWatch Log Group for security services - SOC 2 Control: Logging and Monitoring
resource "aws_cloudwatch_log_group" "security_services" {
  name              = "/aws/security-services/${data.aws_caller_identity.current.account_id}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = merge(
    var.tags,
    {
      Name = "security-services-logs"
    }
  )
}

# IAM Role for Config - SOC 2 Control: Access Control
resource "aws_iam_role" "config_role" {
  name = "aws-config-role-${data.aws_caller_identity.current.account_id}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
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
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "config-s3-policy"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          aws_s3_bucket.security_findings.arn,
          "${aws_s3_bucket.security_findings.arn}/*"
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

# AWS Config Recorder - SOC 2 Control: Compliance Monitoring
resource "aws_config_configuration_recorder" "main" {
  count       = var.enable_config ? 1 : 0
  name        = "security-config-recorder"
  role_arn    = aws_iam_role.config_role.arn
  recording_group {
    all_supported = true
    include_global_resources = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_policy]

  tags = merge(
    var.tags,
    {
      Name = "security-config-recorder"
    }
  )
}

resource "aws_config_configuration_recorder_status" "main" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.main[0].name
  is_enabled         = true
  depends_on         = [aws_s3_bucket_policy.security_findings]
  start_recording    = true
}

resource "aws_config_delivery_channel" "main" {
  count                          = var.enable_config ? 1 : 0
  name                           = "security-config-channel"
  s3_bucket_name                 = aws_s3_bucket.security_findings.id
  sns_topic_arn                  = aws_sns_topic.config_notifications.arn
  include_global_resources       = true
  depends_on                     = [aws_config_configuration_recorder_status.main]

  tags = merge(
    var.tags,
    {
      Name = "security-config-channel"
    }
  )
}

# SNS Topic for Config notifications
resource "aws_sns_topic" "config_notifications" {
  name              = "aws-config-notifications-${data.aws_caller_identity.current.account_id}"
  kms_master_key_id = aws_kms_key.security_services.id

  tags = merge(
    var.tags,
    {
      Name = "config-notifications"
    }
  )
}

resource "aws_sns_topic_policy" "config_notifications" {
  arn = aws_sns_topic.config_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.config_notifications.arn
      }
    ]
  })
}

# GuardDuty Detector - SOC 2 Control: Threat Detection
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
  }

  tags = merge(
    var.tags,
    {
      Name = "security-guardduty-detector"
    }
  )
}

# GuardDuty ThreatIntelSet for custom threat intelligence
resource "aws_guardduty_threatintelset" "main" {
  count              = var.enable_guardduty ? 1 : 0
  detector_id        = aws_guardduty_detector.main[0].id
  activate           = true
  format             = "TXT"
  location           = "${aws_s3_bucket.security_findings.arn}/threat-intel/guardduty-threatintelset.txt"
  name               = "security-threat-intel-set"

  depends_on = [aws_s3_bucket_policy.security_findings]

  tags = merge(
    var.tags,
    {
      Name = "guardduty-threatintelset"
    }
  )
}

# CloudWatch Event Rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count           = var.enable_guardduty ? 1 : 0
  name            = "guardduty-findings-rule"
  description     = "Capture GuardDuty findings"
  event_bus_name  = "default"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type