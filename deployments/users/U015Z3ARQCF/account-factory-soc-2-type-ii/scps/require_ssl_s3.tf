# AWS Service Control Policy (SCP) for Requiring SSL/TLS on S3 Access
# Implements SOC 2 CC6.7 - Encryption in Transit
# Part of AFT Framework - Global Customizations for Organization-wide Guardrails

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
      Compliance = "SOC2-TypeII"
      Framework  = "AFT"
      CreatedAt  = timestamp()
    }
  }
}

# Data source to get the organization root
data "aws_organizations_organization" "root" {}

# Data source to get the current AWS account (should be management account)
data "aws_caller_identity" "current" {}

# SCP Policy Document - Require SSL/TLS for S3 Access
# Denies all S3 actions when aws:SecureTransport is false
# Implements CC6.7 - Encryption in Transit requirement
locals {
  scp_policy_document = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedS3Transport"
        Effect = "Deny"
        Action = [
          "s3:*"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedS3ListBucket"
        Effect = "Deny"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:ListBucketVersions"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  }
}

# Create the SCP for requiring SSL/TLS on S3
resource "aws_organizations_policy" "require_ssl_s3" {
  name            = var.scp_name
  description     = var.scp_description
  type            = "SERVICE_CONTROL_POLICY"
  content         = jsonencode(local.scp_policy_document)
  skip_destroy    = false

  tags = {
    Name        = var.scp_name
    Description = var.scp_description
    Control     = "CC6.7"
    Purpose     = "Enforce encryption in transit for S3"
  }
}

# Attach SCP to root organization if target_ous is empty (apply to all)
# This ensures all accounts in the organization require SSL/TLS for S3
resource "aws_organizations_policy_attachment" "require_ssl_s3_root" {
  count     = length(var.target_ous) == 0 ? 1 : 0
  policy_id = aws_organizations_policy.require_ssl_s3.id
  target_id = data.aws_organizations_organization.root.roots[0].id
}

# Attach SCP to specific OUs if provided
# Allows granular control over which OUs enforce this policy
resource "aws_organizations_policy_attachment" "require_ssl_s3_ou" {
  for_each  = toset(var.target_ous)
  policy_id = aws_organizations_policy.require_ssl_s3.id
  target_id = each.value
}

# CloudWatch Log Group for SCP audit trail
# Retention: 7 years (2555 days) for SOC 2 compliance
resource "aws_cloudwatch_log_group" "scp_audit" {
  name              = "/aws/organizations/scp/${var.scp_name}"
  retention_in_days = 2555

  kms_key_id = aws_kms_key.scp_logs.arn

  tags = {
    Name        = "SCP-Audit-Logs"
    Compliance  = "SOC2-TypeII"
    Retention   = "7-years"
    ManagedBy   = "CARL"
  }
}

# KMS Key for encrypting SCP audit logs
# Implements CC6.1 - Logical access controls
resource "aws_kms_key" "scp_logs" {
  description             = "KMS key for SCP audit logs encryption"
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
          Service = "logs.amazonaws.com"
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
    Name       = "scp-logs-key"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# KMS Key Alias for easier reference
resource "aws_kms_alias" "scp_logs" {
  name          = "alias/scp-audit-logs"
  target_key_id = aws_kms_key.scp_logs.key_id
}

# CloudTrail for tracking SCP policy changes
# Implements CC6.2 - Audit logging for policy modifications
resource "aws_cloudtrail" "scp_changes" {
  name                          = "${var.scp_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Organizations::Policy"
      values = ["arn:aws:organizations::${data.aws_caller_identity.current.account_id}:policy/o-*/service_control_policy/*"]
    }
  }

  tags = {
    Name        = "SCP-Changes-Trail"
    Compliance  = "SOC2-TypeII"
    ManagedBy   = "CARL"
  }
}

# S3 Bucket for CloudTrail logs
# Implements CC6.2 - Audit log storage
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.scp_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "SCP-CloudTrail-Logs"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
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
      kms_master_key_id = aws_kms_key.cloudtrail.arn
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

# Enforce SSL/TLS for CloudTrail bucket
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

# KMS Key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail logs encryption"
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
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:s3:::*"
          }
        }
      }
    ]
  })

  tags = {
    Name       = "cloudtrail-key"
    ManagedBy  = "CARL"
    Compliance = "SOC2-TypeII"
  }
}

# KMS Key Alias for CloudTrail
resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloudtrail-key"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# CloudWatch Alarm for SCP policy changes
# Implements CC6.2 - Monitoring of policy modifications
resource "aws_cloudwatch_metric_alarm" "scp_policy_changes" {
  alarm_name          = "${var.scp_name}-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PolicyChangeCount"
  namespace           = "AWS/Organizations"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert when SCP policies are modified"
  treat_missing_data  = "notBreaching"

  tags = {
    Name       = "SCP-Policy-Changes-Alarm"
    Compliance = "SOC2-TypeII"
    ManagedBy  = "CARL"
  }
}

# Outputs for integration with other AFT modules
output "scp_id" {
  description = "The ID of the created SCP policy"
  value       = aws_organizations_policy.require_ssl_s3.id
}

output "scp_arn" {
  description = "The ARN of the created SCP policy"
  value       = aws_organizations_policy.require_ssl_s3.arn
}

output "scp_name" {
  description = "The name of the created SCP policy"
  value       = aws_organizations_policy.require_ssl_s3.name
}

output "cloudtrail_log_group_name" {
  description = "CloudWatch Log Group for SCP audit trail"
  value       = aws_cloudwatch_log_group.scp_audit.name
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "kms_key_id" {
  description = "KMS key ID for SCP logs encryption"
  value       = aws_kms_key.scp_logs.id
}

output "policy_document" {
  description = "The SCP policy document"
  value       = local.scp_policy_document
  sensitive   = false
}