# AFT Account Request Module for Staging/QA Environment
# Implements AWS Account Factory for Terraform with SOC 2 Type II compliance
# Creates a new AWS account in the Workloads OU with security service enablement

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
  description = "Email for SSO user assignment (optional)"
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

variable "account_tags" {
  description = "Tags to apply to the new account"
  type        = map(string)
  default = {
    OU         = "Workloads"
    Compliance = "SOC2"
    ManagedBy  = "CARL-AccountFactory"
    Environment = "Staging"
  }
}

# Data source to reference the AFT management account
data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {}

# AFT Account Request Module
# This module integrates with AWS Control Tower to provision a new account
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
      Purpose           = "Staging/QA environment"
      ComplianceFramework = "SOC2-Type-II"
      DataClassification = "Internal"
      BackupRequired    = "true"
      LogRetention      = "2555" # 7 years for SOC 2
    }
  )

  # Change management parameters for audit trail
  change_management_parameters = {
    change_requested_by = "Terraform-AFT"
    change_reason       = "Automated account provisioning for Staging/QA environment"
  }

  # Custom fields to trigger security service enablement
  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
    soc2_compliance     = true
  }

  # Select the appropriate customization based on OU
  account_customizations_name = "workloads"
}

# Output the account request details
output "account_request_id" {
  description = "The ID of the account request"
  value       = module.aft_account_request.account_request_id
}

output "account_id" {
  description = "The AWS Account ID of the newly created account"
  value       = module.aft_account_request.account_id
}

output "account_arn" {
  description = "The ARN of the newly created account"
  value       = module.aft_account_request.account_arn
}

output "account_status" {
  description = "The status of the account creation"
  value       = module.aft_account_request.account_status
}

output "account_name" {
  description = "The name of the created account"
  value       = var.account_name
}

output "organizational_unit" {
  description = "The OU where the account was created"
  value       = var.managed_organizational_unit
}

# AFT Account Customization Configuration for Workloads OU
# This file should be placed in: aft-account-customizations/workloads/main.tf

# Terraform configuration for account-specific customizations
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Variables provided by AFT framework
variable "account_id" {
  description = "The new account ID created by AFT"
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

# Provider configuration for the new account
provider "aws" {
  alias  = "new_account"
  region = "us-east-1"

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

# Enable GuardDuty for threat detection (SOC 2 - Monitoring & Detection)
resource "aws_guardduty_detector" "workloads" {
  provider = aws.new_account
  count    = var.enable_guardduty ? 1 : 0

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
    Name        = "workloads-guardduty"
    Purpose     = "Threat detection and monitoring"
    Compliance  = "SOC2"
  }
}

# Enable Security Hub for security posture management (SOC 2 - Security Monitoring)
resource "aws_securityhub_account" "workloads" {
  provider = aws.new_account
  count    = var.enable_security_hub ? 1 : 0

  tags = {
    Name       = "workloads-security-hub"
    Compliance = "SOC2"
  }
}

# Enable AWS Config for compliance monitoring (SOC 2 - Audit & Compliance)
resource "aws_config_configuration_aggregator" "workloads" {
  provider = aws.new_account
  count    = var.enable_config ? 1 : 0
  name     = "workloads-aggregator"

  account_aggregation_sources {
    account_ids = [var.account_id]
    regions     = ["us-east-1", "us-west-2"]
  }

  tags = {
    Name       = "workloads-config-aggregator"
    Compliance = "SOC2"
  }
}

# CloudTrail for audit logging (SOC 2 - Audit Trail)
resource "aws_cloudtrail" "workloads" {
  provider = aws.new_account

  name                          = "workloads-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = {
    Name       = "workloads-cloudtrail"
    Compliance = "SOC2"
  }
}

# S3 bucket for CloudTrail logs with encryption (SOC 2 - Encryption at Rest)
resource "aws_s3_bucket" "cloudtrail_logs" {
  provider = aws.new_account
  bucket   = "workloads-cloudtrail-logs-${var.account_id}"

  tags = {
    Name       = "workloads-cloudtrail-logs"
    Compliance = "SOC2"
  }
}

# Enable versioning for audit trail integrity
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  provider = aws.new_account
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for CloudTrail logs
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  provider = aws.new_account
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access to CloudTrail logs
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  provider = aws.new_account
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  provider = aws.new_account
  bucket   = aws_s3_bucket.cloudtrail_logs.id

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

# CloudWatch Log Group for CloudTrail logs with 7-year retention (SOC 2)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  provider            = aws.new_account
  name                = "/aws/cloudtrail/workloads"
  retention_in_days   = 2555 # 7 years for SOC 2 compliance
  kms_key_id          = aws_kms_key.cloudwatch_logs.arn

  tags = {
    Name       = "workloads-cloudtrail-logs"
    Compliance = "SOC2"
  }
}

# KMS key for CloudWatch Logs encryption (SOC 2 - Encryption at Rest)
resource "aws_kms_key" "cloudwatch_logs" {
  provider                = aws.new_account
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name       = "workloads-cloudwatch-logs-key"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "cloudwatch_logs" {
  provider      = aws.new_account
  name          = "alias/workloads-cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# IAM role for CloudTrail CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_logs_role" {
  provider = aws.new_account
  name     = "cloudtrail-cloudwatch-logs-role"

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
    Name       = "cloudtrail-cloudwatch-logs-role"
    Compliance = "SOC2"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs_policy" {
  provider = aws.new_account
  name     = "cloudtrail-cloudwatch-logs-policy"
  role     = aws_iam_role.cloudtrail_cloudwatch_logs_role.id

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

# VPC Flow Logs for network monitoring (SOC 2 - Monitoring)
resource "aws_flow_log_group" "workloads" {
  provider            = aws.new_account
  name                = "/aws/vpc/flowlogs/workloads"
  retention_in_days   = 2555 # 7 years for SOC 2
  traffic_type        = "ALL"
  log_destination_type = "cloud-watch-logs"
  kms_key_id          = aws_kms_key.vpc_flow_logs.arn

  tags = {
    Name       = "workloads-vpc-flow-logs"
    Compliance = "SOC2"
  }
}

# KMS key for VPC Flow Logs encryption
resource "aws_kms_key" "vpc_flow_logs" {
  provider                = aws.new_account
  description             = "KMS key for VPC Flow Logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name       = "workloads-vpc-flow-logs-key"
    Compliance = "SOC2"
  }
}

resource "aws_kms_alias" "vpc_flow_logs" {
  provider      = aws.new_account
  name          = "alias/workloads-vpc-flow-