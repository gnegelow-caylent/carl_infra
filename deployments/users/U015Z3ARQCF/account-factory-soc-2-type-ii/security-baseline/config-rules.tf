# AWS Config Rules for SOC 2 Type II Compliance
# This module implements AWS Config Rules to ensure continuous compliance monitoring
# across CloudTrail, GuardDuty, S3, EBS, RDS, VPC Flow Logs, and IAM controls

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
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "organization_enabled" {
  description = "Enable AWS Config Rules at organization level"
  type        = bool
  default     = true
}

variable "config_bucket_name" {
  description = "S3 bucket name for AWS Config snapshots"
  type        = string
}

variable "config_bucket_key_prefix" {
  description = "S3 key prefix for Config snapshots"
  type        = string
  default     = "config-snapshots"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days (SOC 2 requires 7 years minimum)"
  type        = number
  default     = 2555
}

variable "iam_password_policy_min_length" {
  description = "Minimum password length for IAM policy"
  type        = number
  default     = 14
}

variable "iam_password_policy_require_symbols" {
  description = "Require symbols in IAM passwords"
  type        = bool
  default     = true
}

variable "iam_password_policy_require_numbers" {
  description = "Require numbers in IAM passwords"
  type        = bool
  default     = true
}

variable "iam_password_policy_require_uppercase" {
  description = "Require uppercase in IAM passwords"
  type        = bool
  default     = true
}

variable "iam_password_policy_require_lowercase" {
  description = "Require lowercase in IAM passwords"
  type        = bool
  default     = true
}

variable "access_key_max_age_days" {
  description = "Maximum age of access keys in days"
  type        = number
  default     = 90
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

# KMS Key for Config encryption
resource "aws_kms_key" "config" {
  description             = "KMS key for AWS Config encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "config-encryption-key"
  }
}

resource "aws_kms_alias" "config" {
  name          = "alias/config-${var.environment}"
  target_key_id = aws_kms_key.config.key_id
}

# S3 bucket for Config snapshots with encryption
resource "aws_s3_bucket" "config" {
  bucket = var.config_bucket_name

  tags = {
    Name = "config-bucket"
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.config.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config.arn}/*"
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
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/*"
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

# IAM Role for AWS Config
resource "aws_iam_role" "config" {
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

  tags = {
    Name = "config-role"
  }
}

resource "aws_iam_role_policy_attachment" "config_managed_policy" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  name = "config-s3-policy"
  role = aws_iam_role.config.id

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
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/${var.config_bucket_key_prefix}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.config.arn
      }
    ]
  })
}

# AWS Config Recorder
resource "aws_config_configuration_recorder" "main" {
  name       = "config-recorder-${var.environment}"
  role_arn   = aws_iam_role.config.arn
  depends_on = [aws_iam_role_policy.config_s3]

  recording_group {
    all_supported = true
    include_global = true
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  name              = aws_config_configuration_recorder.main.name
  is_enabled        = true
  depends_on        = [aws_s3_bucket_policy.config]
  start_recording   = true
}

# AWS Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  name           = "config-delivery-channel-${var.environment}"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_key_prefix  = var.config_bucket_key_prefix
  depends_on     = [aws_config_configuration_recorder_status.main]

  s3_encryption {
    kms_key_arn = aws_kms_key.config.arn
  }
}

# CloudWatch Log Group for Config
resource "aws_cloudwatch_log_group" "config" {
  name              = "/aws/config/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.config.arn

  tags = {
    Name = "config-logs"
  }
}

# Config Rules - CloudTrail Enabled (CC7.2)
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC7.2"
  }
}

# Config Rules - GuardDuty Enabled Centralized (CC7.1)
resource "aws_config_config_rule" "guardduty_enabled" {
  name = "guardduty-enabled-centralized"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC7.1"
  }
}

# Config Rules - S3 Bucket Public Read Prohibited (CC6.7)
resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.7"
  }
}

# Config Rules - S3 Bucket Public Write Prohibited (CC6.7)
resource "aws_config_config_rule" "s3_public_write_prohibited" {
  name = "s3-bucket-public-write-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.7"
  }
}

# Config Rules - S3 Bucket SSL Requests Only (CC6.7)
resource "aws_config_config_rule" "s3_ssl_requests_only" {
  name = "s3-bucket-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.7"
  }
}

# Config Rules - S3 Bucket Server-Side Encryption Enabled (CC6.7)
resource "aws_config_config_rule" "s3_encryption_enabled" {
  name = "s3-bucket-server-side-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.7"
  }
}

# Config Rules - Encrypted Volumes (CC6.7)
resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.7"
  }
}

# Config Rules - RDS Storage Encrypted (CC6.7)
resource "aws_config_config_rule" "rds_storage_encrypted" {
  name = "rds-storage-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.7"
  }
}

# Config Rules - VPC Flow Logs Enabled (CC7.2)
resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  name = "vpc-flow-logs-enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC7.2"
  }
}

# Config Rules - IAM Password Policy (CC6.1)
resource "aws_config_config_rule" "iam_password_policy" {
  name = "iam-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = var.iam_password_policy_require_uppercase
    RequireLowercaseCharacters = var.iam_password_policy_require_lowercase
    RequireSymbols             = var.iam_password_policy_require_symbols
    RequireNumbers             = var.iam_password_policy_require_numbers
    MinimumPasswordLength      = var.iam_password_policy_min_length
    PasswordReusePrevention    = 24
    MaxPasswordAge             = 90
  })

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.1"
  }
}

# Config Rules - IAM User MFA Enabled (CC6.1)
resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  name = "iam-user-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.1"
  }
}

# Config Rules - Root Account MFA Enabled (CC6.1)
resource "aws_config_config_rule" "root_account_mfa_enabled" {
  name = "root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.1"
  }
}

# Config Rules - Access Keys Rotated (CC6.1)
resource "aws_config_config_rule" "access_keys_rotated" {
  name = "access-keys-rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = var.access_key_max_age_days
  })

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Control = "CC6.1"
  }
}

# Config Rules - CMK Backing Key Rotation Enabled (CC6.7)
resource "aws_config_config_rule" "cmk_backing_key