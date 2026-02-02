# AFT Account Request for Network Hub (Shared Services OU)
# SOC 2 Type II Compliant Network Account with Security Services Enabled
# Purpose: Transit Gateway, centralized egress, network inspection

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
      Compliance = "SOC2-TypeII"
      CreatedBy  = "AFT"
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
  description = "Name of the AWS account"
  type        = string
  default     = "network"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test7@test.com"
}

variable "managed_organizational_unit" {
  description = "Organizational Unit where account will be placed"
  type        = string
  default     = "Shared Services"
}

variable "sso_user_email" {
  description = "Email for SSO user (optional)"
  type        = string
  default     = ""
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

# AFT Account Request Module
# This creates the AWS account through Control Tower
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email != "" ? var.sso_user_email : var.account_email
  }

  account_tags = {
    OU          = "Shared Services"
    Purpose     = "Network Hub"
    ManagedBy   = "CARL-AccountFactory"
    Compliance  = "SOC2-TypeII"
    Environment = "Production"
    CostCenter  = "Infrastructure"
  }

  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "Network Hub account for Transit Gateway, centralized egress, and network inspection"
  }

  # Custom fields to trigger security service enablement
  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
  }

  # Select the appropriate customization for Shared Services OU
  account_customizations_name = "infrastructure"
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

output "organizational_unit" {
  description = "The Organizational Unit where the account is placed"
  value       = var.managed_organizational_unit
}

output "security_services_enabled" {
  description = "Security services enabled on the account"
  value = {
    guardduty    = var.enable_guardduty
    security_hub = var.enable_security_hub
    config       = var.enable_config
  }
}

---

# AFT Account Customization for Infrastructure/Network (Shared Services OU)
# File: aft-account-customizations/infrastructure/main.tf
# SOC 2 Type II Compliance: Security baseline, logging, and monitoring

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
  region = data.aws_region.current.name

  default_tags {
    tags = {
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2-TypeII"
      CreatedBy  = "AFT-Customization"
    }
  }
}

# Data sources for AFT context
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period (SOC 2: 7 years)"
  type        = number
  default     = 2555
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
  description             = "KMS key for account-wide encryption (SOC 2 compliance)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "network-account-key"
    Purpose    = "Account-wide encryption"
    Compliance = "SOC2-TypeII"
  }
}

resource "aws_kms_alias" "account_key_alias" {
  name          = "alias/network-account-key"
  target_key_id = aws_kms_key.account_key.key_id
}

# CloudWatch Log Group for centralized logging (SOC 2 requirement)
resource "aws_cloudwatch_log_group" "network_account_logs" {
  name              = "/aws/network-account/logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.account_key.arn

  tags = {
    Name       = "network-account-logs"
    Compliance = "SOC2-TypeII"
  }
}

# CloudTrail for audit logging (SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "network-account-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "network-account-cloudtrail"
    Compliance = "SOC2-TypeII"
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
      }
    ]
  })
}

resource "aws_cloudtrail" "network_account_trail" {
  name                          = "network-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.account_key.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = {
    Name       = "network-account-trail"
    Compliance = "SOC2-TypeII"
  }
}

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "network_account" {
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
    Name       = "network-account-detector"
    Compliance = "SOC2-TypeII"
  }
}

# Security Hub for security posture (SOC 2 requirement)
resource "aws_securityhub_account" "network_account" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name       = "network-account-hub"
    Compliance = "SOC2-TypeII"
  }
}

resource "aws_securityhub_standards_subscription" "cis" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on      = [aws_securityhub_account.network_account]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
  depends_on      = [aws_securityhub_account.network_account]
}

# AWS Config for compliance monitoring (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "network_account" {
  count = var.enable_config ? 1 : 0
  name  = "network-account-aggregator"

  account_aggregation_sources {
    account_ids = [data.aws_caller_identity.current.account_id]
    regions     = [data.aws_region.current.name]
  }

  tags = {
    Name       = "network-account-aggregator"
    Compliance = "SOC2-TypeII"
  }
}

resource "aws_config_configuration_recorder" "network_account" {
  count       = var.enable_config ? 1 : 0
  name        = "network-account-recorder"
  role_arn    = aws_iam_role.config_role[0].arn
  recording_group {
    all_supported = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_policy]
}

resource "aws_config_delivery_channel" "network_account" {
  count           = var.enable_config ? 1 : 0
  name            = "network-account-channel"
  s3_bucket_name  = aws_s3_bucket.config_bucket[0].id
  sns_topic_arn   = aws_sns_topic.config_notifications[0].arn
  depends_on      = [aws_config_configuration_recorder.network_account]
}

resource "aws_config_configuration_recorder_status" "network_account" {
  count       = var.enable_config ? 1 : 0
  name        = aws_config_configuration_recorder.network_account[0].name
  is_enabled  = true
  depends_on  = [aws_config_delivery_channel.network_account]
}

# S3 bucket for Config (SOC 2 requirement)
resource "aws_s3_bucket" "config_bucket" {
  count  = var.enable_config ? 1 : 0
  bucket = "network-account-config-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "network-account-config"
    Compliance = "SOC2-TypeII"
  }
}

resource "aws_s3_bucket_versioning" "config_versioning" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_encryption" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.account_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config_pab" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SNS topic for Config notifications
resource "aws_sns_topic" "config_notifications" {
  count             = var.enable_config ? 1 : 0
  name              = "network-account-config-notifications"
  kms_master_key_id = aws_kms_key.account_key.id

  tags = {
    Name       = "network-account-config-notifications"
    Compliance = "SOC2-TypeII"