# Central Logging Bucket for SOC 2 Type II Compliance
# Implements CC7.2 (Logging), A1.3 (Data Protection)
# Features: KMS encryption, versioning, lifecycle policies, access logging, 7-year retention

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
}

# Variables
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name_suffix" {
  description = "Suffix for central logging bucket name"
  type        = string
  default     = "central-logs"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "organization_name" {
  description = "Organization name for bucket naming"
  type        = string
}

variable "retention_days" {
  description = "Log retention period in days (7 years for SOC 2)"
  type        = number
  default     = 2555
}

variable "transition_to_ia_days" {
  description = "Days before transitioning to Infrequent Access"
  type        = number
  default     = 90
}

variable "transition_to_glacier_days" {
  description = "Days before transitioning to Glacier"
  type        = number
  default     = 365
}

variable "enable_versioning" {
  description = "Enable S3 versioning for data integrity"
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "Enable S3 access logging"
  type        = bool
  default     = true
}

variable "allowed_services" {
  description = "AWS services allowed to write to logging bucket"
  type        = list(string)
  default     = ["cloudtrail.amazonaws.com", "config.amazonaws.com"]
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# KMS Key for S3 encryption
resource "aws_kms_key" "central_logging" {
  description             = "KMS key for central logging bucket encryption (SOC 2 CC7.2)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "${var.organization_name}-central-logging-key"
    }
  )
}

resource "aws_kms_alias" "central_logging" {
  name          = "alias/${var.organization_name}-central-logging"
  target_key_id = aws_kms_key.central_logging.key_id
}

# KMS Key Policy for CloudTrail and Config
resource "aws_kms_key_policy" "central_logging" {
  key_id = aws_kms_key.central_logging.id

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
      },
      {
        Sid    = "Allow Config to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:DecryptDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Access Logging Bucket (separate bucket for S3 access logs)
resource "aws_s3_bucket" "access_logging" {
  bucket = "${var.organization_name}-${var.bucket_name_suffix}-access-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.organization_name}-central-logging-access-logs"
    }
  )
}

# Block public access on access logging bucket
resource "aws_s3_bucket_public_access_block" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encryption for access logging bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.central_logging.arn
    }
    bucket_key_enabled = true
  }
}

# Versioning for access logging bucket
resource "aws_s3_bucket_versioning" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy for access logging bucket
resource "aws_s3_bucket_lifecycle_configuration" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = var.transition_to_ia_days
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    transition {
      days          = var.transition_to_glacier_days
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = var.retention_days
    }
  }
}

# Central Logging Bucket
resource "aws_s3_bucket" "central_logging" {
  bucket = "${var.organization_name}-${var.bucket_name_suffix}-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.organization_name}-central-logging"
    }
  )
}

# Block all public access (SOC 2 A1.3)
resource "aws_s3_bucket_public_access_block" "central_logging" {
  bucket = aws_s3_bucket.central_logging.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for data integrity (SOC 2 CC7.2)
resource "aws_s3_bucket_versioning" "central_logging" {
  bucket = aws_s3_bucket.central_logging.id

  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

# Server-side encryption with KMS (SOC 2 CC7.2)
resource "aws_s3_bucket_server_side_encryption_configuration" "central_logging" {
  bucket = aws_s3_bucket.central_logging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.central_logging.arn
    }
    bucket_key_enabled = true
  }
}

# Enable access logging (SOC 2 CC7.2)
resource "aws_s3_bucket_logging" "central_logging" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.central_logging.id

  target_bucket = aws_s3_bucket.access_logging.id
  target_prefix = "central-logging-access-logs/"
}

# Lifecycle configuration (SOC 2 A1.3 - data retention)
resource "aws_s3_bucket_lifecycle_configuration" "central_logging" {
  bucket = aws_s3_bucket.central_logging.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = var.transition_to_ia_days
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    transition {
      days          = var.transition_to_glacier_days
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = var.retention_days
    }
  }
}

# Bucket policy allowing CloudTrail and Config to write logs
resource "aws_s3_bucket_policy" "central_logging" {
  bucket = aws_s3_bucket.central_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logging.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyIncorrectKMSKey"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logging.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.central_logging.arn
          }
        }
      },
      {
        Sid    = "DenyUnencryptedTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.central_logging.arn,
          "${aws_s3_bucket.central_logging.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logging.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailGetBucketVersioning"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketVersioning"
        Resource = aws_s3_bucket.central_logging.arn
      },
      {
        Sid    = "AllowConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logging.arn}/*"
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
        Resource = aws_s3_bucket.central_logging.arn
      }
    ]
  })
}

# Block public access on access logging bucket policy
resource "aws_s3_bucket_policy" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.access_logging.arn,
          "${aws_s3_bucket.access_logging.arn}/*"
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

# Outputs
output "central_logging_bucket_id" {
  description = "ID of the central logging bucket"
  value       = aws_s3_bucket.central_logging.id
}

output "central_logging_bucket_arn" {
  description = "ARN of the central logging bucket"
  value       = aws_s3_bucket.central_logging.arn
}

output "central_logging_bucket_region" {
  description = "Region of the central logging bucket"
  value       = aws_s3_bucket.central_logging.region
}

output "access_logging_bucket_id" {
  description = "ID of the access logging bucket"
  value       = aws_s3_bucket.access_logging.id
}

output "access_logging_bucket_arn" {
  description = "ARN of the access logging bucket"
  value       = aws_s3_bucket.access_logging.arn
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.central_logging.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.central_logging.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key"
  value       = aws_kms_alias.central_logging.name
}