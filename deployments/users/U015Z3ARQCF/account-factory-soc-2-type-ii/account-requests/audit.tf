# AFT Account Request for Security OU - SOC 2 Type II Compliance
# This module creates an AWS account via Control Tower with security-focused customizations

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
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
      CreatedBy  = "Terraform"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for account configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Name of the AWS account to be created"
  type        = string
  default     = "audit"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test1@test.com"
}

variable "managed_organizational_unit" {
  description = "Organizational Unit where account will be placed"
  type        = string
  default     = "Security"
}

variable "sso_user_email" {
  description = "Email for SSO user (optional)"
  type        = string
  default     = ""
}

variable "account_purpose" {
  description = "Purpose of the account"
  type        = string
  default     = "Security Hub delegated admin, GuardDuty admin, centralized security tools"
}

variable "enable_guardduty" {
  description = "Enable GuardDuty in the account"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub in the account"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config in the account"
  type        = bool
  default     = true
}

variable "account_tags" {
  description = "Tags to apply to the account"
  type        = map(string)
  default = {
    OU         = "Security"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years = 2555 days)"
  type        = number
  default     = 2555
}

# AFT Account Request Module
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
      Compliance = "SOC2-Type-II"
      Encryption = "Required"
      Logging    = "Enabled"
    }
  )

  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "Security account creation for SOC 2 compliance - ${var.account_purpose}"
  }

  custom_fields = {
    enable_guardduty     = var.enable_guardduty
    enable_security_hub  = var.enable_security_hub
    enable_config        = var.enable_config
    soc2_compliance      = true
    encryption_required  = true
    logging_enabled      = true
    log_retention_days   = var.log_retention_days
  }

  account_customizations_name = "security"
}

# Outputs for account creation details
output "account_id" {
  description = "The ID of the newly created AWS account"
  value       = try(module.aft_account_request.account_id, "pending")
}

output "account_arn" {
  description = "The ARN of the newly created AWS account"
  value       = try(module.aft_account_request.account_arn, "pending")
}

output "account_name" {
  description = "The name of the newly created AWS account"
  value       = var.account_name
}

output "account_email" {
  description = "The email of the newly created AWS account"
  value       = var.account_email
}

output "organizational_unit" {
  description = "The Organizational Unit where the account was placed"
  value       = var.managed_organizational_unit
}

output "account_customizations_name" {
  description = "The customization profile applied to this account"
  value       = "security"
}

output "soc2_compliance_enabled" {
  description = "SOC 2 compliance features enabled"
  value = {
    guardduty     = var.enable_guardduty
    security_hub  = var.enable_security_hub
    config        = var.enable_config
    encryption    = true
    logging       = true
    log_retention = "${var.log_retention_days} days"
  }
}

---

# AFT Account Customizations for Security OU
# File: aft-account-customizations/security/main.tf

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
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
      CreatedBy  = "Terraform"
    }
  }
}

# AFT Variables (provided by AFT framework)
variable "account_id" {
  description = "The new account ID"
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

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "enable_guardduty" {
  description = "Enable GuardDuty"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 2555
}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "security_key" {
  description             = "KMS key for security account encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "security-account-key"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "security_key_alias" {
  name          = "alias/security-account-key"
  target_key_id = aws_kms_key.security_key.key_id
}

# CloudWatch Log Group for centralized logging (SOC 2 requirement)
resource "aws_cloudwatch_log_group" "security_logs" {
  name              = "/aws/security-account/centralized-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security_key.arn

  tags = {
    Name       = "security-account-logs"
    Compliance = "SOC2"
  }
}

# CloudTrail for audit trail (SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "security-account-cloudtrail-${var.account_id}"

  tags = {
    Name       = "security-cloudtrail-bucket"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_versioning" {
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
      kms_master_key_id = aws_kms_key.security_key.arn
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

# CloudTrail for audit logging
resource "aws_cloudtrail" "security_trail" {
  name                          = "security-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security_key.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.security_logs.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_role.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = {
    Name       = "security-account-trail"
    Compliance = "SOC2"
  }
}

# IAM Role for CloudTrail
resource "aws_iam_role" "cloudtrail_role" {
  name = "security-cloudtrail-role"

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
    Name       = "security-cloudtrail-role"
    Compliance = "SOC2"
  }
}

resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "security-cloudtrail-policy"
  role = aws_iam_role.cloudtrail_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.security_logs.arn}:*"
      }
    ]
  })
}

# GuardDuty Detector (SOC 2 requirement)
resource "aws_guardduty_detector" "security_detector" {
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
    Name       = "security-guardduty-detector"
    Compliance = "SOC2"
  }
}

# Security Hub (SOC 2 requirement)
resource "aws_securityhub_account" "security_hub" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name       = "security-hub"
    Compliance = "SOC2"
  }
}

resource "aws_securityhub_standards_subscription" "cis_benchmark" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.security_hub]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_account.security_hub]
}

# AWS Config (SOC 2 requirement)
resource "aws_s3_bucket" "config_bucket" {
  count  = var.enable_config ? 1 : 0
  bucket = "security-account-config-${var.account_id}"

  tags = {
    Name       = "security-config-bucket"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_versioning" "config_versioning" {
  count  = var.enable