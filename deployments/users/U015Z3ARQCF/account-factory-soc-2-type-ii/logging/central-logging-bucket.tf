# Central Logging Bucket for SOC 2 Type II Compliance
# Implements CC7.2 (Logging and Monitoring) and A1.3 (Data Protection)
# Provides centralized audit trail with encryption, versioning, and lifecycle management

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

variable "enable_access_logging" {
  description = "Enable S3 access logging"
  type        = bool
  default     = true
}

variable "allowed_services" {
  description = "AWS services allowed to write to the bucket"
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

data "aws_region" "current" {}

# KMS Key for S3 encryption
resource "aws_kms_key" "central_logs" {
  description             = "KMS key for central logging bucket encryption (SOC 2 CC7.2)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "${var.organization_name}-central-logs-key"
    }
  )
}

resource "aws_kms_alias" "central_logs" {
  name          = "alias/${var.organization_name}-central-logs"
  target_key_id = aws_kms_key.central_logs.key_id
}

# KMS Key Policy for CloudTrail and Config
resource "aws_kms_key_policy" "central_logs" {
  key_id = aws_kms_key.central_logs.id

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

# Access logging bucket (separate bucket for S3 access logs)
resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.organization_name}-${var.bucket_name_suffix}-access-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.organization_name}-central-logs-access-logs"
    }
  )
}

# Block public access for access logs bucket
resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encryption for access logs bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.central_logs.arn
    }
    bucket_key_enabled = true
  }
}

# Versioning for access logs bucket
resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy for access logs bucket
resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

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

# Central logging bucket
resource "aws_s3_bucket" "central_logs" {
  bucket = "${var.organization_name}-${var.bucket_name_suffix}-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.organization_name}-central-logs"
    }
  )
}

# Block all public access (SOC 2 A1.3)
resource "aws_s3_bucket_public_access_block" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for data integrity (SOC 2 CC7.2)
resource "aws_s3_bucket_versioning" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption with KMS (SOC 2 CC7.2)
resource "aws_s3_bucket_server_side_encryption_configuration" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.central_logs.arn
    }
    bucket_key_enabled = true
  }
}

# Enable access logging (SOC 2 CC7.2)
resource "aws_s3_bucket_logging" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "central-logs-access/"
}

# Lifecycle configuration (SOC 2 CC7.2)
resource "aws_s3_bucket_lifecycle_configuration" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

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
resource "aws_s3_bucket_policy" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logs.arn}/*"
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
          aws_s3_bucket.central_logs.arn,
          "${aws_s3_bucket.central_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailAcl"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.central_logs.arn
      },
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AllowConfigAcl"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.central_logs.arn
      },
      {
        Sid    = "AllowConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Block object deletion (MFA delete protection)
resource "aws_s3_bucket_object_lock_configuration" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }
}

# Outputs
output "central_logs_bucket_id" {
  description = "ID of the central logging bucket"
  value       = aws_s3_bucket.central_logs.id
}

output "central_logs_bucket_arn" {
  description = "ARN of the central logging bucket"
  value       = aws_s3_bucket.central_logs.arn
}

output "central_logs_bucket_region" {
  description = "Region of the central logging bucket"
  value       = aws_s3_bucket.central_logs.region
}

output "access_logs_bucket_id" {
  description = "ID of the access logs bucket"
  value       = aws_s3_bucket.access_logs.id
}

output "access_logs_bucket_arn" {
  description = "ARN of the access logs bucket"
  value       = aws_s3_bucket.access_logs.arn
}

output "kms_key_id" {
  description = "ID of the KMS key for bucket encryption"
  value       = aws_kms_key.central_logs.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key for bucket encryption"
  value       = aws_kms_key.central_logs.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key"
  value       = aws_kms_alias.central_logs.name
}