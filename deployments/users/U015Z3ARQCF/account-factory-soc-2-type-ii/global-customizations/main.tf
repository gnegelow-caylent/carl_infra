# AWS AFT Global Customizations for SOC 2 Type II Compliance
# This module implements IAM password policy, S3 block public access, and EBS encryption defaults

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

# Variables for configuration
variable "aws_region" {
  description = "AWS region for global customizations"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "password_policy_enabled" {
  description = "Enable IAM password policy"
  type        = bool
  default     = true
}

variable "s3_block_public_access_enabled" {
  description = "Enable S3 block public access"
  type        = bool
  default     = true
}

variable "ebs_encryption_default_enabled" {
  description = "Enable EBS encryption by default"
  type        = bool
  default     = true
}

variable "password_minimum_length" {
  description = "Minimum password length"
  type        = number
  default     = 14
}

variable "password_require_symbols" {
  description = "Require symbols in password"
  type        = bool
  default     = true
}

variable "password_require_numbers" {
  description = "Require numbers in password"
  type        = bool
  default     = true
}

variable "password_require_uppercase" {
  description = "Require uppercase letters in password"
  type        = bool
  default     = true
}

variable "password_require_lowercase" {
  description = "Require lowercase letters in password"
  type        = bool
  default     = true
}

variable "password_max_age_days" {
  description = "Maximum password age in days"
  type        = number
  default     = 90
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords to prevent reuse"
  type        = number
  default     = 24
}

variable "ebs_encryption_kms_key_id" {
  description = "KMS key ID for EBS encryption (optional)"
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# IAM Password Policy for SOC 2 compliance
# Controls: AC-2 (Account Management), IA-5 (Authentication)
resource "aws_iam_account_password_policy" "soc2_compliant" {
  count = var.password_policy_enabled ? 1 : 0

  minimum_password_length        = var.password_minimum_length
  require_lowercase_characters   = var.password_require_lowercase
  require_numbers                = var.password_require_numbers
  require_uppercase_characters   = var.password_require_uppercase
  require_symbols                = var.password_require_symbols
  allow_users_to_change_password = true
  expire_passwords               = true
  max_password_age               = var.password_max_age_days
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = false

  lifecycle {
    ignore_changes = [hard_expiry]
  }
}

# S3 Block Public Access for Account
# Controls: AC-3 (Access Control), AC-6 (Least Privilege)
resource "aws_s3_account_public_access_block" "soc2_compliant" {
  count = var.s3_block_public_access_enabled ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# EBS Encryption by Default
# Controls: SC-7 (Boundary Protection), SC-28 (Protection of Information at Rest)
resource "aws_ec2_ebs_encryption_by_default" "soc2_compliant" {
  count = var.ebs_encryption_default_enabled ? 1 : 0

  enabled = true
}

# KMS Key for EBS Encryption (if not using AWS managed key)
resource "aws_kms_key" "ebs_encryption" {
  description             = "KMS key for EBS encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ebs_kms_policy.json

  tags = merge(
    var.tags,
    {
      Name        = "ebs-encryption-key"
      Environment = var.environment
    }
  )
}

# KMS Key Alias for EBS Encryption
resource "aws_kms_alias" "ebs_encryption" {
  name          = "alias/ebs-encryption-${var.environment}"
  target_key_id = aws_kms_key.ebs_encryption.key_id
}

# KMS Key Policy for EBS Encryption
data "aws_iam_policy_document" "ebs_kms_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow EBS Service"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:CreateGrant",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow CloudWatch Logs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

# Set default EBS encryption key
resource "aws_ec2_default_ebs_encryption" "soc2_compliant" {
  count = var.ebs_encryption_default_enabled ? 1 : 0

  enabled           = true
  kms_key_id        = aws_kms_key.ebs_encryption.arn
  default_kms_key_id = aws_kms_key.ebs_encryption.id

  depends_on = [aws_ec2_ebs_encryption_by_default.soc2_compliant]
}

# CloudTrail for audit logging (SOC 2 requirement)
# Controls: AU-2 (Audit Events), AU-12 (Audit Generation)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = merge(
    var.tags,
    {
      Name        = "cloudtrail-logs"
      Environment = var.environment
    }
  )
}

# Enable versioning on CloudTrail bucket
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption on CloudTrail bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail_encryption.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access to CloudTrail bucket
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy for CloudTrail logs (7-year retention for SOC 2)
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555  # 7 years
    }
  }
}

# KMS key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail_encryption" {
  description             = "KMS key for CloudTrail encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_kms_policy.json

  tags = merge(
    var.tags,
    {
      Name        = "cloudtrail-encryption-key"
      Environment = var.environment
    }
  )
}

# KMS Key Alias for CloudTrail
resource "aws_kms_alias" "cloudtrail_encryption" {
  name          = "alias/cloudtrail-encryption-${var.environment}"
  target_key_id = aws_kms_key.cloudtrail_encryption.key_id
}

# KMS Key Policy for CloudTrail
data "aws_iam_policy_document" "cloudtrail_kms_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow CloudTrail to encrypt logs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = [
      "kms:GenerateDataKey",
      "kms:DecryptDataKey"
    ]
    resources = ["*"]
  }
}

# S3 bucket policy for CloudTrail
data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      service = "cloudtrail.amazonaws.com"
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      service = "cloudtrail.amazonaws.com"
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

# CloudTrail for organization-wide logging
resource "aws_cloudtrail" "organization" {
  name                          = "organization-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail_encryption.arn
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]

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

  tags = merge(
    var.tags,
    {
      Name        = "organization-trail"
      Environment = var.environment
    }
  )
}

# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/organization-${var.environment}"
  retention_in_days = 2555  # 7 years for SOC 2

  kms_key_id = "${aws_kms_key.cloudwatch_logs.arn}:*"

  tags = merge(
    var.tags,
    {
      Name        = "cloudtrail-logs"
      Environment = var.environment
    }
  )
}

# KMS key for CloudWatch Logs
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch Logs encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudwatch_kms_policy.json

  tags = merge(
    var.tags,
    {
      Name        = "cloudwatch-logs-encryption-key"
      Environment = var.environment
    }
  )
}

# KMS Key Alias for CloudWatch Logs
resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/cloudwatch-logs-${var.environment}"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# KMS Key Policy for CloudWatch Logs
data "aws_iam_policy_document" "cloudwatch_kms_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow CloudWatch Logs"
    effect = "Allow"
    principals {
      service = "logs.${data.aws_region.current.name}.amazonaws.com"
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Create