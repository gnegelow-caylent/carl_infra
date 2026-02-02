# AWS Account Factory for Terraform (AFT) Global Customizations
# SOC 2 Type II Compliance Configuration
# Implements IAM password policy, S3 block public access, and EBS encryption defaults

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
      CreatedBy  = "Terraform"
      Environment = var.environment
    }
  }
}

# Variables
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

variable "password_policy_minimum_length" {
  description = "Minimum password length"
  type        = number
  default     = 14
}

variable "password_policy_require_symbols" {
  description = "Require at least one symbol in password"
  type        = bool
  default     = true
}

variable "password_policy_require_numbers" {
  description = "Require at least one number in password"
  type        = bool
  default     = true
}

variable "password_policy_require_uppercase" {
  description = "Require at least one uppercase letter in password"
  type        = bool
  default     = true
}

variable "password_policy_require_lowercase" {
  description = "Require at least one lowercase letter in password"
  type        = bool
  default     = true
}

variable "password_policy_max_age" {
  description = "Maximum password age in days"
  type        = number
  default     = 90
}

variable "password_policy_reuse_prevention" {
  description = "Number of previous passwords to prevent reuse"
  type        = number
  default     = 24
}

variable "password_policy_expiration_warning" {
  description = "Days before password expiration to warn user"
  type        = number
  default     = 14
}

# IAM Password Policy - SOC 2 Control: AC-2 Account Management
resource "aws_iam_account_password_policy" "soc2_compliant" {
  minimum_password_length        = var.password_policy_minimum_length
  require_lowercase_characters   = var.password_policy_require_lowercase
  require_numbers                = var.password_policy_require_numbers
  require_uppercase_characters   = var.password_policy_require_uppercase
  require_symbols                = var.password_policy_require_symbols
  allow_users_to_change_password = true
  expire_passwords               = true
  max_password_age               = var.password_policy_max_age
  password_reuse_prevention      = var.password_policy_reuse_prevention
  hard_expiry                    = false

  depends_on = [aws_iam_role.aft_global_customization_role]
}

# S3 Block Public Access - SOC 2 Control: AC-3 Access Enforcement
resource "aws_s3_account_public_access_block" "global" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# EBS Encryption Default - SOC 2 Control: SC-7 Boundary Protection
resource "aws_ec2_ebs_encryption_by_default" "global" {
  enabled = true
}

# KMS Key for EBS Encryption - SOC 2 Control: SC-13 Cryptographic Protection
resource "aws_kms_key" "ebs_encryption" {
  description             = "KMS key for EBS encryption in AFT global customization"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EBS service"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "aft-ebs-encryption-key"
  }
}

resource "aws_kms_alias" "ebs_encryption" {
  name          = "alias/aft-ebs-encryption"
  target_key_id = aws_kms_key.ebs_encryption.key_id
}

# Set default EBS encryption key
resource "aws_ec2_ebs_default_kms_key" "global" {
  kms_key_id = aws_kms_key.ebs_encryption.arn
}

# CloudTrail for audit logging - SOC 2 Control: AU-2 Audit Events
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "aft-cloudtrail-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name = "aft-cloudtrail-logs"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

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

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    transition {
      days          = 2555
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

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
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# KMS Key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail_encryption" {
  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:DecryptDataKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      }
    ]
  })

  tags = {
    Name = "aft-cloudtrail-encryption-key"
  }
}

resource "aws_kms_alias" "cloudtrail_encryption" {
  name          = "alias/aft-cloudtrail-encryption"
  target_key_id = aws_kms_key.cloudtrail_encryption.key_id
}

# CloudTrail for global account activity
resource "aws_cloudtrail" "global" {
  name                          = "aft-global-trail"
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
      values = ["arn:aws:s3:::*/"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }

  tags = {
    Name = "aft-global-trail"
  }
}

# CloudWatch Log Group for CloudTrail - SOC 2 Control: AU-12 Audit Generation
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/aft-global"
  retention_in_days = 2555

  kms_key_id = "${aws_kms_key.cloudwatch_logs.arn}:*"

  tags = {
    Name = "aft-cloudtrail-logs"
  }
}

# KMS Key for CloudWatch Logs encryption
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
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
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name = "aft-cloudwatch-logs-key"
  }
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/aft-cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# IAM Role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_logs" {
  name = "aft-cloudtrail-cloudwatch-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "aft-cloudtrail-cloudwatch-logs-role"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs" {
  name = "aft-cloudtrail-cloudwatch-logs-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# Update CloudTrail with CloudWatch Logs
resource "aws_cloudtrail" "global_with_logs" {
  name                          = "aft-global-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail_encryption.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_logs.arn
  depends_on                    = [aws_s3_bucket_