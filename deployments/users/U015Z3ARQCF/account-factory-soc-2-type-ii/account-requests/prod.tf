# AFT Account Request Module for Production Workloads
# Implements SOC 2 Type II compliance controls
# Creates AWS account via Control Tower with security baseline

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

# Variables for account request configuration
variable "aws_region" {
  description = "AWS region for account creation"
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Name of the AWS account to be created"
  type        = string
  default     = "prod"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test5@test.com"
}

variable "managed_organizational_unit" {
  description = "Organizational Unit where account will be placed"
  type        = string
  default     = "Workloads"
}

variable "sso_user_email" {
  description = "Email for SSO user (optional)"
  type        = string
  default     = ""
}

variable "account_purpose" {
  description = "Purpose of the account"
  type        = string
  default     = "Production workloads"
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
  description = "CloudWatch Logs retention period in days (SOC 2: 7 years = 2555 days)"
  type        = number
  default     = 2555
}

variable "account_tags" {
  description = "Tags to apply to the account"
  type        = map(string)
  default = {
    OU         = "Workloads"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

# Data source for Control Tower management account
data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {}

# AFT Account Request Module
# Uses official AWS Control Tower Account Factory for Terraform
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
      Purpose    = var.account_purpose
      CreatedBy  = "Terraform-AFT"
      Compliance = "SOC2-Type-II"
    }
  )

  change_management_parameters = {
    change_requested_by = "terraform-automation"
    change_type         = "New Account"
    notes               = "SOC 2 Type II compliant production account for ${var.account_purpose}"
  }

  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
  }

  account_customizations_name = "workloads"
}

# Outputs for account creation details
output "account_id" {
  description = "ID of the newly created AWS account"
  value       = try(module.aft_account_request.account_id, "pending")
}

output "account_arn" {
  description = "ARN of the newly created AWS account"
  value       = try(module.aft_account_request.account_arn, "pending")
}

output "account_name" {
  description = "Name of the newly created AWS account"
  value       = var.account_name
}

output "organizational_unit" {
  description = "Organizational Unit where account is placed"
  value       = var.managed_organizational_unit
}

output "account_email" {
  description = "Email address of the newly created AWS account"
  value       = var.account_email
}

output "sso_user_email" {
  description = "SSO user email for account access"
  value       = var.sso_user_email != "" ? var.sso_user_email : var.account_email
}

output "security_services_enabled" {
  description = "Security services enabled on the account"
  value = {
    guardduty    = var.enable_guardduty
    security_hub = var.enable_security_hub
    config       = var.enable_config
  }
}

output "compliance_framework" {
  description = "Compliance framework applied to account"
  value       = "SOC 2 Type II"
}

output "log_retention_days" {
  description = "CloudWatch Logs retention period for audit trail"
  value       = var.log_retention_days
}

# AFT Account Customization for Workloads OU
# This file should be placed in: aft-account-customizations/workloads/main.tf

# Security baseline customization for production workloads
# Implements SOC 2 Type II controls

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

  assume_role {
    role_arn = "arn:aws:iam::${var.account_id}:role/AWSControlTowerExecution"
  }

  default_tags {
    tags = {
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
    }
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "account_id" {
  description = "Account ID where customization is applied"
  type        = string
}

variable "ct_management_account_id" {
  description = "Control Tower management account ID"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log archive account ID"
  type        = string
}

variable "audit_account_id" {
  description = "Audit account ID"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 2555
}

# KMS Key for encryption at rest (SOC 2 control)
resource "aws_kms_key" "account_key" {
  description             = "KMS key for SOC 2 encryption at rest in account ${var.account_id}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "account-encryption-key"
    Purpose    = "SOC2-Encryption-At-Rest"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "account_key_alias" {
  name          = "alias/account-${var.account_id}-key"
  target_key_id = aws_kms_key.account_key.key_id
}

# CloudTrail for audit logging (SOC 2 control)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloudtrail-logs-${var.account_id}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "cloudtrail-logs"
    Purpose    = "SOC2-Audit-Trail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_bucket_versioning" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.account_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_pab" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

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
        Resource = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
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
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
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
          aws_s3_bucket.cloudtrail_bucket.arn,
          "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
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

# CloudTrail trail for account activity logging
resource "aws_cloudtrail" "account_trail" {
  name                          = "account-${var.account_id}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.account_key.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = {
    Name       = "account-trail"
    Purpose    = "SOC2-Audit-Trail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# CloudWatch Log Group for CloudTrail logs
resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/aws/cloudtrail/account-${var.account_id}"
  retention_in_days = var.log_retention_days

  kms_key_id = "${aws_kms_key.account_key.arn}:*"

  tags = {
    Name       = "cloudtrail-logs"
    Purpose    = "SOC2-Audit-Trail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# IAM Role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
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
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "cloudtrail-cloudwatch-logs-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
      }
    ]
  })
}

# Update CloudTrail to include CloudWatch Logs
resource "aws_cloudtrail" "account_trail_with_logs" {
  name                          = "account-${var.account_id}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.account_key.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_role.arn

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_policy,
    aws_iam_role_policy.cloudtrail_cloudwatch_policy
  ]

  tags = {
    Name       = "account-trail"
    Purpose    = "SOC2-Audit-Trail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# GuardDuty for threat detection (SOC 2 control)
resource "aws_guardduty_detector" "account_detector" {
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