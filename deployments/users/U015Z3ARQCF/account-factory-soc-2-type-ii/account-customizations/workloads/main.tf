# AFT Account Customization for Workloads OU with SOC 2 Type II Security Services
# This module configures GuardDuty, Security Hub, and AWS Config for compliance monitoring

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
      Compliance = "SOC2-TypeII"
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

variable "config_delivery_frequency" {
  description = "AWS Config delivery frequency"
  type        = string
  default     = "TwentyFour_Hours"
}

variable "guardduty_finding_publishing_frequency" {
  description = "GuardDuty finding publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "organization_id" {
  description = "AWS Organization ID for multi-account setup"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default = {
    Project     = "AccountCustomization"
    CostCenter  = "Security"
    Compliance  = "SOC2-TypeII"
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "security_services" {
  description             = "KMS key for security services encryption (SOC 2 Type II)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-security-services-key"
    }
  )
}

resource "aws_kms_alias" "security_services" {
  name          = "alias/${var.environment}-security-services"
  target_key_id = aws_kms_key.security_services.key_id
}

# S3 bucket for Config and GuardDuty logs (SOC 2 audit trail requirement)
resource "aws_s3_bucket" "security_logs" {
  bucket = "security-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-security-logs"
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

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

# S3 bucket policy for Config and GuardDuty
resource "aws_s3_bucket_policy" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.security_logs.arn,
          "${aws_s3_bucket.security_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowConfigDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AllowConfigGetBucketVersioning"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketVersioning"
        Resource = aws_s3_bucket.security_logs.arn
      },
      {
        Sid    = "AllowGuardDutyDelivery"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/guardduty/*"
      }
    ]
  })
}

# CloudWatch Log Group for Config (SOC 2 logging requirement)
resource "aws_cloudwatch_log_group" "config_logs" {
  name              = "/aws/config/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-config-logs"
    }
  )
}

# IAM Role for AWS Config (SOC 2 access control requirement)
resource "aws_iam_role" "config_role" {
  name = "${var.environment}-config-role"

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

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "${var.environment}-config-s3-policy"
  role = aws_iam_role.config_role.id

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
          "${aws_s3_bucket.security_logs.arn}/config/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.security_services.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.config_logs.arn}:*"
      }
    ]
  })
}

# AWS Config Recorder (SOC 2 compliance monitoring)
resource "aws_config_configuration_recorder" "main" {
  count       = var.enable_config ? 1 : 0
  name        = "${var.environment}-recorder"
  role_arn    = aws_iam_role.config_role.arn
  depends_on  = [aws_iam_role_policy.config_s3_policy]

  recording_group {
    all_supported = true
    include_global_resources = data.aws_region.current.name == "us-east-1" ? true : false
  }

  tags = var.tags
}

resource "aws_config_configuration_recorder_status" "main" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.main[0].name
  is_enabled         = true
  depends_on         = [aws_s3_bucket_policy.security_logs]
  start_recording    = true
}

# AWS Config Delivery Channel (SOC 2 audit trail)
resource "aws_config_delivery_channel" "main" {
  count                          = var.enable_config ? 1 : 0
  name                           = "${var.environment}-delivery-channel"
  s3_bucket_name                 = aws_s3_bucket.security_logs.id
  s3_key_prefix                  = "config"
  sns_topic_arn                  = aws_sns_topic.config_notifications.arn
  depends_on                     = [aws_config_configuration_recorder_status.main]

  depends_on = [aws_s3_bucket_policy.security_logs]
}

# SNS Topic for Config notifications
resource "aws_sns_topic" "config_notifications" {
  name              = "${var.environment}-config-notifications"
  kms_master_key_id = aws_kms_key.security_services.id

  tags = var.tags
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

# GuardDuty Detector (SOC 2 threat detection)
resource "aws_guardduty_detector" "main" {
  count            = var.enable_guardduty ? 1 : 0
  enable           = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency

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

  tags = var.tags
}

# GuardDuty ThreatIntel Set (optional, for custom threat intelligence)
resource "aws_guardduty_threatintelset" "main" {
  count              = var.enable_guardduty ? 1 : 0
  activate           = true
  detector_id        = aws_guardduty_detector.main[0].id
  format             = "TXT"
  location           = "${aws_s3_bucket.security_logs.arn}/guardduty/threatintel.txt"
  name               = "${var.environment}-threatintel-set"
  depends_on         = [aws_s3_bucket_policy.security_logs]
}

# CloudWatch Log Group for GuardDuty findings
resource "aws_cloudwatch_log_group" "guardduty_logs" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/guardduty/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-guardduty-logs"
    }
  )
}

# EventBridge Rule for GuardDuty findings to CloudWatch Logs
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${var.environment}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "guardduty_logs" {
  count             = var.enable_guardduty ? 1 : 0
  rule              = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id         = "GuardDutyLogsTarget"
  arn               = aws_cloudwatch_log_group.guardduty_logs[0].arn
  role_arn          = aws_iam_role.eventbridge_role[0].arn
}

# IAM Role for EventBridge
resource "aws_iam_role" "eventbridge_role" {
  count = var.enable_guardduty ? 1 : 0
  name  = "${var.environment}-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "eventbridge_policy" {
  count = var.enable_guardduty ? 1 : 0
  name  = "${var.