# AWS Security Services Module - SOC 2 Type II Compliance
# Implements GuardDuty, Security Hub, AWS Config, and Inspector
# for comprehensive threat detection, compliance monitoring, and vulnerability management

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
  description = "Enable GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub for compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for configuration recording"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable Inspector for vulnerability scanning"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Macie for data classification"
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
  description = "Record all supported AWS resources in Config"
  type        = bool
  default     = true
}

variable "inspector_resource_types" {
  description = "Inspector resource types to scan"
  type        = list(string)
  default     = ["EC2", "ECR", "LAMBDA"]
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (SOC 2 requires 7 years)"
  type        = number
  default     = 2555
}

variable "s3_log_bucket_prefix" {
  description = "S3 bucket prefix for security logs"
  type        = string
  default     = "security-logs"
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# KMS Key for encrypting security logs and findings
resource "aws_kms_key" "security_services" {
  description             = "KMS key for security services encryption (SOC 2 CC6.1)"
  deletion_window_in_days = 10
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

# S3 bucket for security logs and findings
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

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

resource "aws_s3_bucket_logging" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  target_bucket = aws_s3_bucket.security_logs.id
  target_prefix = "access-logs/"
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

# GuardDuty Detector (SOC 2 CC7.1 - Threat Detection)
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

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(
    var.tags,
    {
      Name = "guardduty-detector"
    }
  )
}

# GuardDuty ThreatIntelSet for custom threat intelligence
resource "aws_guardduty_threatintelset" "main" {
  count = var.enable_guardduty ? 1 : 0

  activate       = true
  detector_id    = aws_guardduty_detector.main[0].id
  format         = "TXT"
  location       = "${aws_s3_bucket.security_logs.arn}/guardduty/threat-intel-set.txt"
  name           = "custom-threat-intel"

  depends_on = [aws_s3_bucket.security_logs]
}

# Security Hub (SOC 2 CC7.2 - Compliance Monitoring)
resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0

  tags = merge(
    var.tags,
    {
      Name = "security-hub"
    }
  )
}

# Enable CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis_aws_foundations" {
  count = var.enable_security_hub && contains(var.security_hub_standards, "CIS AWS Foundations") ? 1 : 0

  depends_on = [aws_securityhub_account.main]

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# Enable AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "aws_fsbp" {
  count = var.enable_security_hub && contains(var.security_hub_standards, "AWS Foundational Security Best Practices") ? 1 : 0

  depends_on = [aws_securityhub_account.main]

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# AWS Config (SOC 2 CC7.2 - Configuration Recording)
resource "aws_config_configuration_aggregator" "main" {
  count = var.enable_config ? 1 : 0
  name  = "security-aggregator-${var.environment}"

  account_aggregation_sources {
    account_ids = [data.aws_caller_identity.current.account_id]
    regions     = [var.aws_region]
  }

  tags = merge(
    var.tags,
    {
      Name = "config-aggregator"
    }
  )
}

# IAM Role for AWS Config
resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0
  name  = "aws-config-role-${var.environment}"

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
      Name = "config-role"
    }
  )
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_config ? 1 : 0
  name  = "config-s3-policy"
  role  = aws_iam_role.config[0].id

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
  count       = var.enable_config ? 1 : 0
  name        = "security-recorder-${var.environment}"
  role_arn    = aws_iam_role.config[0].arn
  depends_on  = [aws_iam_role_policy_attachment.config_policy]

  recording_group {
    all_supported = var.config_all_supported
    include_global = true
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.main[0].name
  is_enabled         = true
  depends_on         = [aws_config_delivery_channel.main]
  start_recording    = true
}

# AWS Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  count           = var.enable_config ? 1 : 0
  name            = "security-delivery-channel-${var.environment}"
  s3_bucket_name  = aws_s3_bucket.security_logs.id
  depends_on      = [aws_iam_role_policy.config_s3]

  s3_key_prefix = var.s3_log_bucket_prefix

  sns_topic_arn = aws_sns_topic.config_notifications[0].arn

  depends_on = [aws_iam_role_policy.config_s3]
}

# SNS Topic for Config Notifications
resource "aws_sns_topic" "config_notifications" {
  count             = var.enable_config ? 1 : 0
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

# Inspector (SOC 2 CC7.1 - Vulnerability Scanning)
resource "aws_inspector_resource_group" "main" {
  count = var.enable_inspector ? 1 : 0

  filter {
    key   = "EC2_INSTANCE_TAG_KEY"
    value = "Inspector"
  }

  tags = merge(
    var.tags,
    {
      Name = "inspector-resource-group"
    }
  )
}

resource "aws_inspector_assessment_target" "main" {
  count             = var.enable_inspector ? 1 : 0
  name              = "security-assessment-target-${var.environment}"
  resource_group_arn = aws_inspector_resource_group.main[0].arn

  tags = merge(
    var.tags,
    {
      Name = "inspector-target"
    }
  )
}

# Inspector Assessment Template
resource "aws_inspector_assessment_template" "main" {
  count              = var.enable_inspector ? 1 : 0
  name               = "security-assessment-template-${var.environment}"
  target_arn         = aws_inspector_assessment_target.main[0].arn
  duration           = 3600
  rules_package_arns = data.aws_inspector_rules_packages.main.arns

  tags = merge(
    var.tags,
    {
      Name = "inspector-template"
    }
  )
}

# Data source for Inspector rules packages
data "aws_inspector_rules_packages" "main" {
  filter = "ACTIVE"
}

# Macie (Optional - for S3 data classification)
resource "aws_macie2_account" "main" {
  count = var.enable_macie ? 1