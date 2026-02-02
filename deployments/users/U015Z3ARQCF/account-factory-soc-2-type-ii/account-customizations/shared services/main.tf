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
      CreatedAt  = timestamp()
      Environment = var.environment
    }
  }
}

# Variables for customization
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "shared-services"
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
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years)"
  type        = number
  default     = 2555
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for audit logging"
  type        = bool
  default     = true
}

variable "s3_bucket_prefix" {
  description = "Prefix for S3 bucket names"
  type        = string
  default     = "soc2-compliance"
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 30
}

# KMS Key for encryption at rest
resource "aws_kms_key" "compliance" {
  description             = "KMS key for SOC 2 compliance encryption"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  tags = {
    Name = "soc2-compliance-key"
  }
}

resource "aws_kms_alias" "compliance" {
  name          = "alias/soc2-compliance"
  target_key_id = aws_kms_key.compliance.key_id
}

# S3 bucket for CloudTrail and Config logs with encryption
resource "aws_s3_bucket" "compliance_logs" {
  bucket = "${var.s3_bucket_prefix}-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "compliance-logs-bucket"
  }
}

resource "aws_s3_bucket_versioning" "compliance_logs" {
  bucket = aws_s3_bucket.compliance_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_logs" {
  bucket = aws_s3_bucket.compliance_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.compliance.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "compliance_logs" {
  bucket = aws_s3_bucket.compliance_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "compliance_logs" {
  bucket = aws_s3_bucket.compliance_logs.id

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

resource "aws_s3_bucket_policy" "compliance_logs" {
  bucket = aws_s3_bucket.compliance_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.compliance_logs.arn}/*"
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
          aws_s3_bucket.compliance_logs.arn,
          "${aws_s3_bucket.compliance_logs.arn}/*"
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

# CloudWatch Log Group for centralized logging
resource "aws_cloudwatch_log_group" "compliance" {
  name              = "/aws/compliance/soc2"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.compliance.arn

  tags = {
    Name = "soc2-compliance-logs"
  }
}

# CloudTrail for audit logging
resource "aws_cloudtrail" "compliance" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = "soc2-compliance-trail"
  s3_bucket_name                = aws_s3_bucket.compliance_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.compliance_logs]

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

  event_selector {
    read_write_type           = "All"
    include_management_events = false

    data_resource {
      type   = "AWS::RDS::DBCluster"
      values = ["arn:aws:rds:*:*:cluster/*"]
    }
  }

  tags = {
    Name = "soc2-compliance-trail"
  }
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "compliance" {
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
  }

  tags = {
    Name = "soc2-guardduty-detector"
  }
}

# CloudWatch Event Rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

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

resource "aws_cloudwatch_event_target" "guardduty_log_group" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "GuardDutyToCloudWatch"
  arn       = aws_cloudwatch_log_group.compliance.arn
}

# Security Hub for security posture management
resource "aws_securityhub_account" "compliance" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name = "soc2-security-hub"
  }
}

resource "aws_securityhub_standards_subscription" "cis" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.compliance]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_account.compliance]
}

# AWS Config for compliance monitoring
resource "aws_config_configuration_aggregator" "organization" {
  count = var.enable_config ? 1 : 0

  name = "soc2-organization-aggregator"

  account_aggregation_sources {
    all_regions = true
  }

  tags = {
    Name = "soc2-config-aggregator"
  }
}

resource "aws_config_configuration_recorder" "compliance" {
  count = var.enable_config ? 1 : 0

  name       = "soc2-config-recorder"
  role_arn   = aws_iam_role.config_role[0].arn
  depends_on = [aws_iam_role_policy_attachment.config_policy]

  recording_group {
    all_supported = true
    include_global = true
  }
}

resource "aws_config_configuration_recorder_status" "compliance" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.compliance[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.compliance]
}

resource "aws_config_delivery_channel" "compliance" {
  count = var.enable_config ? 1 : 0

  name           = "soc2-config-channel"
  s3_bucket_name = aws_s3_bucket.compliance_logs.id
  depends_on     = [aws_config_configuration_recorder.compliance]

  s3_key_prefix = "config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  count = var.enable_config ? 1 : 0

  name = "soc2-config-role"

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
    Name = "soc2-config-role"
  }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  count = var.enable_config ? 1 : 0

  role       = aws_iam_role.config_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  count = var.enable_config ? 1 : 0

  name = "soc2-config-s3-policy"
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
          aws_s3_bucket.compliance_logs.arn,
          "${aws_s3_bucket.compliance_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.compliance.arn
      }
    ]
  })
}

# Config Rules for SOC 2 compliance
resource "aws_config_config_rule" "encrypted_volumes" {
  count = var.enable_config ? 1 : 0

  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.compliance]

  tags = {
    Name = "encrypted-volumes-rule"
  }
}

resource "aws_config_config_rule" "root_account_mfa" {
  count = var.enable_config ? 1 : 0

  name = "root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.compliance]

  tags = {
    Name = "root-account-mfa-rule"
  }
}

resource "aws_config_config_rule" "iam_policy_no_statements_with_admin_access" {
  count = var.enable_config ? 1 : 0

  name = "iam-policy-no-statements-with-admin-access"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.compliance]

  tags = {
    Name = "iam-admin-access-rule"
  }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_config ? 1 : 0

  name = "cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.compliance]

  tags = {
    Name = "cloudtrail-enabled-rule"
  }
}

resource "aws_config_config_rule" "s3_bucket_server_side_encryption_enabled" {
  count = var.enable_config ? 1 : 0

  name = "s3-bucket-server-side-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.compliance]

  tags = {
    Name = "s3-encryption-rule"
  }
}

resource "aws_config_config_rule" "rds_encryption_enable