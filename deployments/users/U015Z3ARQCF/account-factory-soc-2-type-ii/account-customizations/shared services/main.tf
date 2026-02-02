# AFT Account Customization for Shared Services OU with SOC 2 Type II Compliance
# Enables GuardDuty, Security Hub, and AWS Config for centralized security monitoring

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
      Purpose    = "SharedServicesAccountCustomization"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
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
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years minimum for audit logs)"
  type        = number
  default     = 2555
}

variable "kms_key_rotation_enabled" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

variable "organization_id" {
  description = "AWS Organization ID for centralized security services"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID for shared services"
  type        = string
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "security_services" {
  description             = "KMS key for security services encryption (SOC 2 Type II)"
  deletion_window_in_days = 30
  enable_key_rotation     = var.kms_key_rotation_enabled
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
          "kms:GenerateDataKey",
          "kms:Decrypt"
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
          "kms:GenerateDataKey",
          "kms:Decrypt"
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
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "security-services-key"
  }
}

resource "aws_kms_alias" "security_services" {
  name          = "alias/security-services-${var.account_id}"
  target_key_id = aws_kms_key.security_services.key_id
}

# S3 Bucket for centralized logging (SOC 2 requirement)
resource "aws_s3_bucket" "security_logs" {
  bucket = "security-logs-${var.account_id}-${data.aws_region.current.name}"

  tags = {
    Name = "security-logs-bucket"
  }
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

# CloudWatch Log Group for security services (SOC 2 requirement)
resource "aws_cloudwatch_log_group" "security_services" {
  name              = "/aws/security-services/shared-account"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_services.arn

  tags = {
    Name = "security-services-logs"
  }
}

# GuardDuty Detector (SOC 2 requirement for threat detection)
resource "aws_guardduty_detector" "shared_services" {
  count = var.enable_guardduty ? 1 : 0

  enable = true

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
    Name = "shared-services-guardduty"
  }
}

# GuardDuty ThreatIntel Feed
resource "aws_guardduty_threatintelset" "shared_services" {
  count = var.enable_guardduty ? 1 : 0

  activate       = true
  detector_id    = aws_guardduty_detector.shared_services[0].id
  format         = "TXT"
  location       = "s3://${aws_s3_bucket.security_logs.id}/guardduty-threatintel/"
  name           = "shared-services-threatintel"
  depends_on     = [aws_s3_bucket.security_logs]
}

# Security Hub (SOC 2 requirement for security posture management)
resource "aws_securityhub_account" "shared_services" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name = "shared-services-security-hub"
  }
}

# Enable Security Hub Standards
resource "aws_securityhub_standards_subscription" "cis_aws_foundations" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on      = [aws_securityhub_account.shared_services]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
  depends_on      = [aws_securityhub_account.shared_services]
}

# AWS Config (SOC 2 requirement for compliance monitoring)
resource "aws_config_configuration_aggregator" "organization" {
  count = var.enable_config ? 1 : 0
  name  = "organization-aggregator"

  account_aggregation_sources {
    all_regions = true
  }

  tags = {
    Name = "organization-config-aggregator"
  }
}

# Config Recorder
resource "aws_config_configuration_recorder" "shared_services" {
  count           = var.enable_config ? 1 : 0
  name            = "shared-services-recorder"
  role_arn        = aws_iam_role.config_role[0].arn
  recording_group {
    all_supported = true
    include_global_resources = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_policy]
}

resource "aws_config_configuration_recorder_status" "shared_services" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.shared_services[0].name
  is_enabled         = true
  depends_on         = [aws_config_delivery_channel.shared_services]
}

# Config Delivery Channel
resource "aws_config_delivery_channel" "shared_services" {
  count           = var.enable_config ? 1 : 0
  name            = "shared-services-channel"
  s3_bucket_name  = aws_s3_bucket.security_logs.id
  sns_topic_arn   = aws_sns_topic.config_notifications[0].arn
  depends_on      = [aws_config_configuration_recorder.shared_services]

  s3_key_prefix = "config/"

  depends_on = [aws_s3_bucket_policy.config_bucket_policy]
}

# SNS Topic for Config Notifications
resource "aws_sns_topic" "config_notifications" {
  count             = var.enable_config ? 1 : 0
  name              = "config-notifications"
  kms_master_key_id = aws_kms_key.security_services.id

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

# IAM Role for Config
resource "aws_iam_role" "config_role" {
  count = var.enable_config ? 1 : 0
  name  = "config-role"

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

  tags = {
    Name = "config-role"
  }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  count = var.enable_config ? 1 : 0
  name  = "config-s3-policy"
  role  = aws_iam_role.config_role[0].id

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
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.security_services.arn
      }
    ]
  })
}

# S3 Bucket Policy for Config
resource "aws_s3_bucket_policy" "config_bucket_policy" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.security_logs.id

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
        Resource = aws_s3_bucket.security_logs.arn
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.security_logs.arn
      },
      {
        Sid    = "AWSConfigBucketPutObject"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/*"
      }
    ]
  })
}

# CloudTrail for audit logging (SOC 2 requirement)
resource "aws_cloudtrail" "security_services" {
  name                          = "security-services-trail"
  s3_bucket_name                = aws_s3_bucket.security_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
  kms_key_id                    = aws_kms_key.security_services.arn

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
    Name = "security-services-trail"
  }
}

# S3 Bucket Policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail