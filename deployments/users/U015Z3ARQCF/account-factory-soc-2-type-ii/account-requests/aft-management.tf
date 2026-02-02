# AFT Account Request Module for Shared Services OU
# Provisions AWS account via Control Tower with SOC 2 compliance controls
# Integrates with AWS Account Factory for Terraform framework

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
  description = "AWS region for account provisioning"
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Name of the AWS account to be created"
  type        = string
  default     = "aft-management"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  sensitive   = true
}

variable "managed_organizational_unit" {
  description = "Organizational Unit where account will be placed"
  type        = string
  default     = "Shared Services"
}

variable "sso_user_email" {
  description = "Email address for SSO user in the account"
  type        = string
  sensitive   = true
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
  description = "Tags to apply to the account"
  type        = map(string)
  default = {
    OU         = "Infrastructure"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
  }
}

# Data source to get current AWS account (management account)
data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {}

# AFT Account Request Module
# Uses official AWS Account Factory for Terraform module
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  # Control Tower account creation parameters
  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email
  }

  # Account tags for metadata and compliance tracking
  account_tags = merge(
    var.account_tags,
    {
      Purpose        = "Account Factory for Terraform - manages account provisioning"
      Environment    = "Shared Services"
      CostCenter     = "Infrastructure"
      DataClassification = "Internal"
    }
  )

  # Change management parameters for audit trail (SOC 2 requirement)
  change_management_parameters = {
    change_requested_by = "Terraform-AFT"
    change_reason       = "Account provisioning via Account Factory for Terraform"
  }

  # Custom fields to trigger security service enablement
  custom_fields = {
    enable_guardduty     = var.enable_guardduty
    enable_security_hub  = var.enable_security_hub
    enable_config        = var.enable_config
  }

  # Select account customization based on OU
  account_customizations_name = "infrastructure"
}

# Outputs for account information
output "account_id" {
  description = "ID of the newly created AWS account"
  value       = try(module.aft_account_request.account_id, "")
}

output "account_arn" {
  description = "ARN of the newly created AWS account"
  value       = try(module.aft_account_request.account_arn, "")
}

output "account_name" {
  description = "Name of the newly created AWS account"
  value       = var.account_name
}

output "organizational_unit" {
  description = "Organizational Unit where account is placed"
  value       = var.managed_organizational_unit
}

output "sso_user_email" {
  description = "SSO user email for account access"
  value       = var.sso_user_email
  sensitive   = true
}

output "customization_name" {
  description = "Account customization profile applied"
  value       = "infrastructure"
}

---

# AFT Account Customizations - Infrastructure OU
# Applied to accounts in Shared Services OU with SOC 2 compliance controls
# File: aft-account-customizations/infrastructure/main.tf

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
      CreatedBy  = "Terraform"
    }
  }
}

# AFT provided variables
variable "account_id" {
  description = "Account ID being customized"
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

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "account_key" {
  description             = "KMS key for account encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "aft-account-key"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "account_key_alias" {
  name          = "alias/aft-account-${var.account_id}"
  target_key_id = aws_kms_key.account_key.key_id
}

# CloudTrail for audit logging (SOC 2 requirement - 7 year retention)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "aft-cloudtrail-${var.account_id}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "aft-cloudtrail-bucket"
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

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555  # 7 years for SOC 2 compliance
    }
  }
}

data "aws_caller_identity" "current" {}

# CloudTrail configuration
resource "aws_cloudtrail" "account_trail" {
  name                          = "aft-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.account_key.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = {
    Name       = "aft-account-trail"
    Compliance = "SOC2"
  }
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

# GuardDuty for threat detection (SOC 2 requirement)
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
    Name       = "aft-guardduty-detector"
    Compliance = "SOC2"
  }
}

# Security Hub for security posture (SOC 2 requirement)
resource "aws_securityhub_account" "account_hub" {}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  depends_on       = [aws_securityhub_account.account_hub]
  standards_arn    = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on       = [aws_securityhub_account.account_hub]
  standards_arn    = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.2.0"
}

# AWS Config for compliance monitoring (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "account_aggregator" {
  name = "aft-account-aggregator"

  account_aggregation_sources {
    account_ids = [var.account_id]
    regions     = [var.aws_region]
  }

  tags = {
    Name       = "aft-account-aggregator"
    Compliance = "SOC2"
  }
}

resource "aws_config_configuration_recorder" "account_recorder" {
  name       = "aft-account-recorder"
  role_arn   = aws_iam_role.config_role.arn
  depends_on = [aws_iam_role_policy_attachment.config_policy]

  recording_group {
    all_supported = true
    include_global = true
  }
}

resource "aws_config_configuration_recorder_status" "account_recorder_status" {
  name       = aws_config_configuration_recorder.account_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.account_channel]
}

resource "aws_config_delivery_channel" "account_channel" {
  name           = "aft-account-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.id
  depends_on     = [aws_config_configuration_recorder.account_recorder]

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

resource "aws_s3_bucket" "config_bucket" {
  bucket = "aft-config-${var.account_id}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "aft-config-bucket"
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
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.account_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config_pab" {
  bucket = aws_s3_bucket.config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Role for Config
resource "aws_iam_role" "config_role" {
  name = "aft-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name       = "aft-config-role"
    Compliance = "SOC2"
  }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "aft-config-s3-policy"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"