# AFT Account Request Module for Security OU
# Creates a new AWS account via Control Tower with SOC 2 compliance configuration
# Account will be used for Security Hub delegated admin, GuardDuty admin, and centralized security tools

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
  description = "AWS region for the account"
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
  description = "The target OU for the account"
  type        = string
  default     = "Security"
}

variable "sso_user_email" {
  description = "Email address for SSO user (optional)"
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
  description = "Additional tags for the account"
  type        = map(string)
  default = {
    OU         = "Security"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

# AFT Account Request Module
# This module integrates with AWS Control Tower to create a new account
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  # Control Tower account parameters
  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email != "" ? var.sso_user_email : var.account_email
  }

  # Account tags for metadata and compliance tracking
  account_tags = merge(
    var.account_tags,
    {
      Purpose           = var.account_purpose
      ComplianceFramework = "SOC2-Type-II"
      SecurityServices  = "GuardDuty,SecurityHub,Config"
      LogRetention      = "2555" # 7 years in days
    }
  )

  # Change management parameters for audit trail (SOC 2 requirement)
  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "Security account creation for centralized security tools and compliance monitoring"
  }

  # Custom fields to trigger security customizations
  custom_fields = {
    enable_guardduty     = var.enable_guardduty
    enable_security_hub  = var.enable_security_hub
    enable_config        = var.enable_config
    compliance_framework = "SOC2"
    account_type         = "security"
  }

  # Select the security customization template
  account_customizations_name = "security"
}

# Outputs for account creation details
output "account_id" {
  description = "The ID of the newly created AWS account"
  value       = module.aft_account_request.account_id
}

output "account_arn" {
  description = "The ARN of the newly created AWS account"
  value       = module.aft_account_request.account_arn
}

output "account_name" {
  description = "The name of the newly created AWS account"
  value       = var.account_name
}

output "account_email" {
  description = "The email address of the newly created AWS account"
  value       = var.account_email
}

output "organizational_unit" {
  description = "The organizational unit where the account was created"
  value       = var.managed_organizational_unit
}

output "account_tags" {
  description = "Tags applied to the account"
  value       = module.aft_account_request.account_tags
}

---

# AFT Account Customization for Security OU
# File: aft-account-customizations/security/main.tf
# Applied after account creation to configure security services

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
    }
  }
}

# AFT provided variables
variable "account_id" {
  description = "The ID of the account being customized"
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

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "security_key" {
  description             = "KMS key for security account encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "security-account-key"
    Purpose    = "Encryption at rest for security services"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "security_key_alias" {
  name          = "alias/security-account-key"
  target_key_id = aws_kms_key.security_key.key_id
}

# CloudTrail for audit logging (SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "cloudtrail-logs"
    Purpose    = "CloudTrail audit logs"
    Compliance = "SOC2"
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
      kms_master_key_id = aws_kms_key.security_key.arn
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

    expiration {
      days = 2555 # 7 years for SOC 2 compliance
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

# CloudTrail for audit trail (SOC 2 requirement)
resource "aws_cloudtrail" "security_account" {
  count = var.enable_config ? 1 : 0

  name                          = "security-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security_key.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Name       = "security-account-trail"
    Purpose    = "Audit trail for compliance"
    Compliance = "SOC2"
  }
}

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "security_account" {
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
    Name       = "security-account-detector"
    Purpose    = "Threat detection and monitoring"
    Compliance = "SOC2"
  }
}

# Security Hub for centralized security findings (SOC 2 requirement)
resource "aws_securityhub_account" "security_account" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name       = "security-account-hub"
    Purpose    = "Centralized security findings"
    Compliance = "SOC2"
  }
}

resource "aws_securityhub_standards_subscription" "cis" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.security_account]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_account.security_account]
}

# AWS Config for compliance monitoring (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "security_account" {
  count = var.enable_config ? 1 : 0
  name  = "security-account-aggregator"

  account_aggregation_sources {
    all_regions = true
    account_ids = [var.account_id]
  }

  tags = {
    Name       = "security-account-aggregator"
    Purpose    = "Compliance monitoring"
    Compliance = "SOC2"
  }
}

resource "aws_config_configuration_recorder" "security_account" {
  count = var.enable_config ? 1 : 0
  name  = "security-account-recorder"

  role_arn = aws_iam_role.config_role[0].arn

  recording_group {
    all_supported = true
    include_global = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_policy]
}

resource "aws_config_configuration_recorder_status" "security_account" {
  count = var.enable_config ? 1 : 0

  name              = aws_config_configuration_recorder.security_account[0].name
  is_enabled        = true
  depends_on        = [aws_config_delivery_channel.security_account]
  start_recording   = true
}

resource "aws_config_delivery_channel" "security_account" {
  count = var.enable_config ? 1 : 0

  name           = "security-account-channel"
  s3_bucket_name = aws_s3_bucket.config_logs[0].id

  depends_on = [aws_config_configuration_recorder.security_account]
}

resource "aws_s3_bucket" "config_logs" {
  count  = var.enable_config ? 1 : 0
  bucket = "config-logs-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "config-logs"
    Purpose    = "AWS Config logs"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_versioning" "config_logs" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_logs" {
  count  = var.enable_config ? 1 : 0
  bucket =