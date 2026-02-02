# AFT Account Request for Log Archive - SOC 2 Type II Compliance
# This module creates a new AWS account via Control Tower with security baseline configuration

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
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
      CreatedBy  = "Terraform"
      CreatedAt  = timestamp()
    }
  }
}

# Data source for Control Tower management account
data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {}

# AFT Account Request Module - Creates account via Control Tower
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email != "" ? var.sso_user_email : var.account_email
  }

  account_tags = merge(
    var.account_tags,
    {
      OU         = var.managed_organizational_unit
      Compliance = "SOC2"
      ManagedBy  = "CARL-AccountFactory"
      Purpose    = "Centralized Logging and Security"
      Environment = "Security"
    }
  )

  change_management_parameters = {
    change_requested_by = var.change_requested_by
    change_reason       = "SOC 2 Type II Compliance - Centralized logging account for CloudTrail, Config, and VPC Flow Logs"
  }

  custom_fields = {
    enable_guardduty     = var.enable_guardduty
    enable_security_hub  = var.enable_security_hub
    enable_config        = var.enable_config
    enable_cloudtrail    = true
    enable_vpc_flow_logs = true
    log_retention_days   = var.log_retention_days
  }

  account_customizations_name = "security"
}

# Outputs for account creation details
output "account_id" {
  description = "The AWS Account ID of the newly created account"
  value       = module.aft_account_request.account_id
}

output "account_arn" {
  description = "The ARN of the newly created account"
  value       = module.aft_account_request.account_arn
}

output "account_name" {
  description = "The name of the newly created account"
  value       = var.account_name
}

output "account_email" {
  description = "The email address associated with the account"
  value       = var.account_email
}

output "organizational_unit" {
  description = "The Organizational Unit where the account was created"
  value       = var.managed_organizational_unit
}

# AFT Account Customization - Security OU Configuration
# File: aft-account-customizations/security/main.tf

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
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
    }
  }
}

# KMS Key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "cloudtrail-encryption-key"
    Purpose    = "CloudTrail Log Encryption"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloudtrail-logs"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# KMS Key for S3 bucket encryption
resource "aws_kms_key" "s3_logs" {
  description             = "KMS key for S3 log bucket encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "s3-logs-encryption-key"
    Purpose    = "S3 Log Bucket Encryption"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "s3_logs" {
  name          = "alias/s3-logs-encryption"
  target_key_id = aws_kms_key.s3_logs.key_id
}

# S3 Bucket for CloudTrail logs - Immutable storage
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "cloudtrail-logs"
    Purpose    = "Centralized CloudTrail Logs"
    Compliance = "SOC2"
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for immutability
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Disabled"
  }
}

# Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_logs.arn
    }
    bucket_key_enabled = true
  }
}

# Enable logging
resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  target_bucket = aws_s3_bucket.cloudtrail_logs.id
  target_prefix = "access-logs/"
}

# Bucket policy for CloudTrail
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
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
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

# Lifecycle policy for log retention (7 years for SOC 2)
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
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

# CloudTrail for organization-wide logging
resource "aws_cloudtrail" "organization" {
  name                          = "organization-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
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
    Name       = "organization-trail"
    Compliance = "SOC2"
  }
}

# CloudWatch Logs group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/organization"
  retention_in_days = var.log_retention_days

  tags = {
    Name       = "cloudtrail-logs"
    Compliance = "SOC2"
  }
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "cloudtrail-cloudwatch-logs-role"

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
    Name       = "cloudtrail-cloudwatch-role"
    Compliance = "SOC2"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "cloudtrail-cloudwatch-logs-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

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
resource "aws_cloudtrail" "organization_with_logs" {
  name                          = aws_cloudtrail.organization.name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn
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
    Name       = "organization-trail"
    Compliance = "SOC2"
  }
}

# AWS Config for compliance monitoring
resource "aws_config_configuration_aggregator" "organization" {
  name = "organization-aggregator"

  account_aggregation_sources {
    all_regions = true
  }

  tags = {
    Name       = "organization-aggregator"
    Compliance = "SOC2"
  }
}

# S3 bucket for Config snapshots
resource "aws_s3_bucket" "config_bucket" {
  bucket = "aws-config-bucket-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "config-bucket"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_public_access_block" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_logs.arn
    }
    bucket_key_enabled = true
  }
}

# Config bucket policy
resource "aws_s3_bucket_policy" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.config_bucket.arn,
          "${aws_s3_bucket.config_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport