# AFT Account Request Module for Production Workloads
# Implements SOC 2 Type II compliant AWS account provisioning via AWS Control Tower
# This module creates a new managed account with security baselines and compliance controls

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
  description = "The target OU for the account"
  type        = string
  default     = "Workloads"
}

variable "sso_user_email" {
  description = "Email address for SSO user (optional)"
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

variable "account_tags" {
  description = "Additional tags for the account"
  type        = map(string)
  default = {
    OU         = "Workloads"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years)"
  type        = number
  default     = 2555
}

# Data source to reference Control Tower management account
data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {}

# AFT Account Request Module
# This module integrates with AWS Control Tower to provision a new managed account
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  # Control Tower account creation parameters
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
      ComplianceFramework = "SOC2-TypeII"
      EncryptionEnabled = "true"
      LoggingEnabled    = "true"
      AuditTrailEnabled = "true"
    }
  )

  # Change management parameters for audit trail (SOC 2 requirement)
  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "Automated account provisioning for ${var.account_purpose}"
  }

  # Custom fields to trigger security customizations
  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
    soc2_compliance     = "true"
    encryption_enabled  = "true"
  }

  # Select the appropriate customization based on OU
  account_customizations_name = var.managed_organizational_unit == "Workloads" ? "workloads" : "default"
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
  description = "The email address of the newly created AWS account"
  value       = var.account_email
}

output "organizational_unit" {
  description = "The organizational unit where the account was created"
  value       = var.managed_organizational_unit
}

output "account_status" {
  description = "Status of the account creation request"
  value       = try(module.aft_account_request.account_status, "PENDING")
}

output "customization_name" {
  description = "The customization template applied to this account"
  value       = var.managed_organizational_unit == "Workloads" ? "workloads" : "default"
}

---

# AFT Account Customizations for Workloads OU
# Applies SOC 2 Type II security baselines to production workload accounts
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

  default_tags {
    tags = {
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2"
    }
  }
}

# AFT-provided variables for account context
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

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days (SOC 2: 7 years)"
  type        = number
  default     = 2555
}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "workload_key" {
  description             = "KMS key for workload account encryption (SOC 2 compliance)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "workload-encryption-key"
    Purpose     = "SOC2-Encryption-AtRest"
    ManagedBy   = "CARL-AccountFactory"
    Compliance  = "SOC2"
  }
}

resource "aws_kms_alias" "workload_key_alias" {
  name          = "alias/workload-encryption"
  target_key_id = aws_kms_key.workload_key.key_id
}

# CloudWatch Log Group for centralized logging (SOC 2 requirement)
resource "aws_cloudwatch_log_group" "workload_logs" {
  name              = "/aws/workload/account-${var.account_id}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.workload_key.arn

  tags = {
    Name       = "workload-logs"
    Purpose    = "SOC2-AuditTrail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# CloudTrail for API audit logging (SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloudtrail-logs-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "cloudtrail-bucket"
    Purpose    = "SOC2-AuditTrail"
    ManagedBy  = "CARL-AccountFactory"
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
      kms_master_key_id = aws_kms_key.workload_key.arn
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
      }
    ]
  })
}

resource "aws_cloudtrail" "workload_trail" {
  name                          = "workload-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_policy]

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

  tags = {
    Name       = "workload-trail"
    Purpose    = "SOC2-AuditTrail"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "workload" {
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
    Name       = "workload-guardduty"
    Purpose    = "SOC2-ThreatDetection"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

# Security Hub for compliance monitoring (SOC 2 requirement)
resource "aws_securityhub_account" "workload" {}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.workload]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.workload]
}

# AWS Config for compliance tracking (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "workload" {
  name = "workload-aggregator"

  account_aggregation_sources {
    account_ids = [var.account_id]
    regions     = [var.aws_region]
  }

  tags = {
    Name       = "workload-config-aggregator"
    Purpose    = "SOC2-ComplianceTracking"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_config_configuration_recorder" "workload" {
  name       = "workload-recorder"
  role_arn   = aws_iam_role.config_role.arn
  depends_on = [aws_iam_role_policy_attachment.config_policy]

  recording_group {
    all_supported = true
    include_global = true
  }
}

resource "aws_config_configuration_recorder_status" "workload" {
  name       = aws_config_configuration_recorder.workload.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.workload]
}

resource "aws_config_delivery_channel" "workload" {
  name           = "workload-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.id
  depends_on     = [aws_config_configuration_recorder.workload]
}

resource "aws_s3_bucket" "config_bucket" {
  bucket = "aws-config-bucket-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "config-bucket"
    Purpose    = "SOC2-ComplianceTracking"
    ManagedBy  = "CARL-AccountFactory"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_versioning" "config_versioning" {
  bucket = aws_s3_bucket.config_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_encryption" {
  bucket = aws_s3_bucket.config_bucket.id

  rule {
    apply_