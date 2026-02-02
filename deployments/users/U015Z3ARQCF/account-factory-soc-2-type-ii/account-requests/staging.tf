# AFT Account Request Module for Staging/QA Environment
# Deploys a new AWS account via AWS Control Tower with SOC 2 compliance controls
# Integrates with AWS Account Factory for Terraform (AFT) framework

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
  description = "AWS region for the account request"
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Name of the AWS account to be created"
  type        = string
  default     = "staging"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test4@test.com"
}

variable "managed_organizational_unit" {
  description = "The target OU for the account"
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
  default     = "Staging/QA environment"
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub for compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for resource compliance tracking"
  type        = bool
  default     = true
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

variable "ct_management_account_id" {
  description = "Control Tower management account ID"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log archive account ID for centralized logging"
  type        = string
}

variable "audit_account_id" {
  description = "Audit account ID for compliance monitoring"
  type        = string
}

# AFT Account Request Module
# This module integrates with AWS Control Tower to provision a new account
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
      Environment = "Staging"
      Purpose     = var.account_purpose
      SOC2Type    = "Type II"
    }
  )

  # Change management parameters for audit trail (SOC 2 requirement)
  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "Automated account provisioning for ${var.account_purpose}"
  }

  # Custom fields to trigger security service enablement
  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
  }

  # Select the appropriate customization based on OU
  account_customizations_name = "workloads"
}

# Data source to retrieve the newly created account information
data "aws_organizations_organization" "current" {}

# Outputs for account information
output "account_id" {
  description = "The ID of the newly created AWS account"
  value       = module.aft_account_request.account_id
}

output "account_arn" {
  description = "The ARN of the newly created AWS account"
  value       = module.aft_account_request.account_arn
}

output "account_email" {
  description = "The email address of the newly created AWS account"
  value       = var.account_email
}

output "account_name" {
  description = "The name of the newly created AWS account"
  value       = var.account_name
}

output "organizational_unit" {
  description = "The organizational unit where the account was created"
  value       = var.managed_organizational_unit
}

output "account_customizations_name" {
  description = "The customization profile applied to the account"
  value       = "workloads"
}

output "sso_user_email" {
  description = "The SSO user email for account access"
  value       = var.sso_user_email != "" ? var.sso_user_email : var.account_email
}

---

# AFT Account Customizations for Workloads OU - Security Configuration
# Applied after account creation to enable SOC 2 compliance controls
# File: aft-account-customizations/workloads/main.tf

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
    role_arn = "arn:aws:iam::${var.account_id}:role/AWSAFTExecution"
  }

  default_tags {
    tags = {
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
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
resource "aws_kms_key" "account_key" {
  description             = "KMS key for account-level encryption at rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "account-encryption-key"
    Purpose    = "SOC2-Encryption-AtRest"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "account_key_alias" {
  name          = "alias/account-encryption-${var.account_id}"
  target_key_id = aws_kms_key.account_key.key_id
}

# CloudTrail for audit logging (SOC 2 requirement - 7 year retention)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "cloudtrail-logs"
    Purpose    = "SOC2-AuditTrail"
    ManagedBy  = "CARL-AccountFactory"
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
      kms_master_key_id = aws_kms_key.account_key.arn
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
    id     = "archive-after-90-days"
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

resource "aws_cloudtrail" "account_trail" {
  count = var.enable_config ? 1 : 0

  name                          = "account-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.account_key.arn
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Name       = "account-audit-trail"
    Purpose    = "SOC2-AuditTrail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "account_detector" {
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
    Name       = "account-threat-detection"
    Purpose    = "SOC2-ThreatDetection"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# Security Hub for compliance monitoring (SOC 2 requirement)
resource "aws_securityhub_account" "account_hub" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name       = "account-security-hub"
    Purpose    = "SOC2-ComplianceMonitoring"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_securityhub_standards_subscription" "cis_benchmark" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.account_hub]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.account_hub]
}

# AWS Config for resource compliance tracking (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "account_aggregator" {
  count = var.enable_config ? 1 : 0
  name  = "account-config-aggregator"

  account_aggregation_sources {
    account_ids = [var.account_id]
    regions     = [var.aws_region]
  }

  tags = {
    Name       = "account-config-aggregator"
    Purpose    = "SOC2-ComplianceTracking"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_config_configuration_recorder" "account_recorder" {
  count = var.enable_config ? 1 : 0
  name  = "account-config-recorder"

  recording_group {
    all_supported = true
    include_global_resources = true
  }

  depends_on = [aws_config_configuration_aggregator.account_aggregator]

  tags = {
    Name       = "account-config-recorder"
    Purpose    = "SOC2-ComplianceTracking"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_config_configuration_recorder_status" "account_recorder" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.