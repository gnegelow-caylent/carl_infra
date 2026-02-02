# AFT Account Request for Network Hub (Shared Services OU)
# SOC 2 Type II Compliant Network Account with Security Services
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
  description = "AWS region for account creation"
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
  description = "Target OU for account placement"
  type        = string
  default     = "Shared Services"
}

variable "sso_user_email" {
  description = "SSO user email for account access"
  type        = string
  default     = ""
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
  description = "Enable AWS Config for configuration tracking"
  type        = bool
  default     = true
}

variable "account_tags" {
  description = "Tags to apply to the account"
  type        = map(string)
  default = {
    OU        = "Shared Services"
    Purpose   = "Network Hub"
    ManagedBy = "CARL-AccountFactory"
  }
}

# AFT Account Request Module
# This creates the account request that Control Tower will process
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request?ref=1.10.1"

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
      Environment = "Shared-Services"
      CostCenter  = "Infrastructure"
      DataClass   = "Internal"
    }
  )

  # Change management parameters for audit trail (SOC 2 requirement)
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

  # Select the appropriate customization for this OU
  account_customizations_name = "infrastructure"
}

# Outputs for account creation tracking
output "account_request_id" {
  description = "AFT account request ID"
  value       = module.aft_account_request.account_request_id
}

output "account_id" {
  description = "AWS Account ID created by AFT"
  value       = try(module.aft_account_request.account_id, "pending")
}

output "account_name" {
  description = "Name of the created account"
  value       = var.account_name
}

output "organizational_unit" {
  description = "Target organizational unit"
  value       = var.managed_organizational_unit
}

output "security_services_enabled" {
  description = "Security services enabled for this account"
  value = {
    guardduty    = var.enable_guardduty
    security_hub = var.enable_security_hub
    config       = var.enable_config
  }
}

---

# AFT Account Customization for Infrastructure/Network OU
# SOC 2 Type II Compliant Security Baseline
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
  region = data.aws_region.current.name

  default_tags {
    tags = {
      ManagedBy  = "CARL-AccountFactory"
      Compliance = "SOC2-TypeII"
      CreatedBy  = "AFT-Customization"
    }
  }
}

# Data sources for account context
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Variables for customization
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
  description = "CloudWatch log retention in days (SOC 2: 7 years)"
  type        = number
  default     = 2555
}

# KMS Key for encryption at rest (SOC 2 requirement)
resource "aws_kms_key" "account_key" {
  description             = "KMS key for account-level encryption (SOC 2 Type II)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name      = "account-encryption-key"
    Purpose   = "SOC2-Encryption-AtRest"
    ManagedBy = "CARL-AccountFactory"
  }
}

resource "aws_kms_alias" "account_key_alias" {
  name          = "alias/account-${data.aws_caller_identity.current.account_id}"
  target_key_id = aws_kms_key.account_key.key_id
}

# CloudTrail for audit logging (SOC 2 requirement)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = {
    Name      = "cloudtrail-logs"
    Purpose   = "SOC2-AuditTrail"
    ManagedBy = "CARL-AccountFactory"
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

resource "aws_cloudtrail" "account_trail" {
  name                          = "account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }

  tags = {
    Name      = "account-cloudtrail"
    Purpose   = "SOC2-AuditTrail"
    ManagedBy = "CARL-AccountFactory"
  }
}

# CloudWatch Log Group for CloudTrail (SOC 2 requirement)
resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/aws/cloudtrail/account-trail"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.account_key.arn

  tags = {
    Name      = "cloudtrail-logs"
    Purpose   = "SOC2-AuditTrail"
    ManagedBy = "CARL-AccountFactory"
  }
}

resource "aws_cloudtrail_event_selector" "log_group" {
  trail_name = aws_cloudtrail.account_trail.name

  depends_on = [aws_cloudwatch_log_group.cloudtrail_logs]
}

# IAM Role for CloudTrail to write to CloudWatch Logs
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
    Name      = "cloudtrail-logs-role"
    ManagedBy = "CARL-AccountFactory"
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

# GuardDuty for threat detection (SOC 2 requirement)
resource "aws_guardduty_detector" "account" {
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
    Name      = "account-guardduty"
    Purpose   = "SOC2-ThreatDetection"
    ManagedBy = "CARL-AccountFactory"
  }
}

# Security Hub for compliance monitoring (SOC 2 requirement)
resource "aws_securityhub_account" "account" {
  count = var.enable_security_hub ? 1 : 0

  tags = {
    Name      = "account-security-hub"
    Purpose   = "SOC2-ComplianceMonitoring"
    ManagedBy = "CARL-AccountFactory"
  }
}

resource "aws_securityhub_standards_subscription" "cis" {
  count           = var.enable_security_hub ? 1 : 0
  standards_arn   = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on      = [aws_securityhub_account.account]
}

# AWS Config for configuration tracking (SOC 2 requirement)
resource "aws_config_configuration_aggregator" "account" {
  count = var.enable_config ? 1 : 0
  name  = "account-aggregator"

  account_aggregation_sources {
    account_ids = [data.aws_caller_identity.current.account_id]
    regions     = [data.aws_region.current.name]
  }

  tags = {
    Name      = "account-config-aggregator"
    Purpose   = "SOC2-ConfigurationTracking"
    ManagedBy = "CARL-AccountFactory"
  }
}

resource "aws_config_configuration_recorder" "account" {
  count = var.enable_config ? 1 : 0
  name  = "account-recorder"

  recording_group {
    all_supported = true
    include_global = true
  }

  depends_on = [aws_iam_role_policy.config_policy]
}

resource "aws_config_configuration_recorder_status" "account" {
  count       = var.enable_config ? 1 : 0
  name        = aws_config_configuration_recorder.account[0].name
  is_enabled  = true
  depends_on  = [aws_config_delivery_channel.account]
}

resource "aws_config_delivery_channel" "account" {
  count = var.enable_config ? 1 : 0
  name  = "account-channel"

  s3_bucket_name = aws_s3_bucket.config_bucket[0].id

  depends_on = [aws_config_configuration_recorder.account]
}

resource "aws_s3_bucket" "config_bucket" {
  count  = var.enable_config ? 1 : 0
  bucket = "aws-config-bucket-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = {
    Name      = "config-bucket"
    Purpose   = "SOC2-ConfigurationTracking