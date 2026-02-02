# AFT Account Request Module for Development Environment
# SOC 2 Type II Compliant AWS Account Vending
# This module creates a new AWS account via Control Tower with security baselines

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
  default     = "dev"
}

variable "account_email" {
  description = "Email address for the AWS account"
  type        = string
  default     = "test3@test.com"
}

variable "managed_organizational_unit" {
  description = "The target OU for the account"
  type        = string
  default     = "Workloads"
}

variable "sso_user_email" {
  description = "Email for SSO user assignment (optional)"
  type        = string
  default     = ""
}

variable "account_purpose" {
  description = "Purpose of the account"
  type        = string
  default     = "Development environment"
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
  description = "Enable AWS Config for configuration compliance"
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

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years minimum)"
  type        = number
  default     = 2555
}

# Data source to get current AWS account (management account)
data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {}

# AFT Account Request Module
# This calls the official AWS Control Tower Account Factory module
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
      Environment = "Development"
    }
  )

  change_management_parameters = {
    change_requested_by = "CARL-AccountFactory"
    change_reason       = "SOC 2 Type II Compliant Account Vending"
  }

  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
  }

  account_customizations_name = "workloads"
}

# Outputs for account request
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
  description = "The OU where the account was created"
  value       = var.managed_organizational_unit
}

output "customization_applied" {
  description = "The customization template applied to the account"
  value       = "workloads"
}

output "soc2_compliance_status" {
  description = "SOC 2 compliance features enabled"
  value = {
    guardduty    = var.enable_guardduty
    security_hub = var.enable_security_hub
    config       = var.enable_config
    encryption   = true
    logging      = true
  }
}

# AFT Account Customization - Workloads OU Security Baseline
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

# AFT Context Variables (provided by AFT framework)
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
  description = "CloudWatch Logs retention (SOC 2: 7 years = 2555 days)"
  type        = number
  default     = 2555
}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "workload_key" {
  description             = "KMS key for workload account encryption - SOC 2 compliant"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "workload-encryption-key"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "workload_key_alias" {
  name          = "alias/workload-${var.account_id}"
  target_key_id = aws_kms_key.workload_key.key_id
}

# CloudTrail for audit logging (SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${var.account_id}-${var.aws_region}"

  tags = {
    Name       = "CloudTrail Logs"
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
      kms_master_key_id = aws_kms_key.workload_key.arn
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
      }
    ]
  })
}

# CloudTrail configuration
resource "aws_cloudtrail" "workload_trail" {
  name                          = "workload-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.workload_key.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Name       = "Workload Account Trail"
    Compliance = "SOC2"
  }
}

# CloudWatch Log Group for CloudTrail (SOC 2 audit trail)
resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/aws/cloudtrail/workload-account"
  retention_in_days = var.log_retention_days

  kms_key_id = "${aws_kms_key.workload_key.arn}:*"

  tags = {
    Name       = "CloudTrail Logs"
    Compliance = "SOC2"
  }
}

resource "aws_iam_role" "cloudtrail_logs_role" {
  name = "cloudtrail-logs-role"

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
    Compliance = "SOC2"
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs_policy" {
  name = "cloudtrail-logs-policy"
  role = aws_iam_role.cloudtrail_logs_role.id

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

resource "aws_cloudtrail_event_selector" "workload_trail" {
  trail_name = aws_cloudtrail.workload_trail.name

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

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "workload" {
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
    Name       = "Workload GuardDuty"
    Compliance = "SOC2"
  }
}

# Security Hub for compliance monitoring (SOC 2 requirement)
resource "aws_securityhub_account" "workload" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name       = "Workload Security Hub"
    Compliance = "SOC2"
  }
}

resource "aws_securityhub_standards_subscription" "cis" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on      = [aws_securityhub_account.workload]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"
  depends_on      = [aws_securityhub_account.workload]
}

# AWS Config for configuration compliance (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "workload" {
  count = var.enable_config ? 1 : 0
  name  = "workload-aggregator"

  account_aggregation_sources {
    account_ids = [var.account_id]
    regions     = [var.aws_region]
  }

  tags = {
    Name       = "Workload Config Aggregator"
    Compliance = "SOC2"
  }
}

resource "aws_config_configuration_recorder" "workload" {
  count       = var.enable_config ? 1 : 0
  name        = "workload-recorder"
  role_arn    = aws_iam_role.config_role[0].arn
  recording_group {
    all_supported = true
  }

  depends_on = [aws_iam_role_policy.config_policy]
}

resource "aws_config_configuration_recorder_status" "workload" {
  count              = var.enable_config ? 1 : 0
  name               = aws_config_configuration_recorder.workload[0].name
  is_enabled         = true
  depends_on         =