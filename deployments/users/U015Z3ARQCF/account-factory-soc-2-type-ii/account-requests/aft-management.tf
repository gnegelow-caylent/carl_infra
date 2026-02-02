# AFT Account Request Module for Shared Services OU
# Provisions a new AWS account via AWS Control Tower with SOC 2 compliance controls
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
      ManagedBy  = "CARL"
      Compliance = "SOC2TypeII"
      Framework  = "AFT"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for AFT Account Request
variable "aws_region" {
  description = "AWS region for AFT operations"
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
  default     = "test@test.com"
}

variable "managed_organizational_unit" {
  description = "Target Organizational Unit for the account"
  type        = string
  default     = "Shared Services"
}

variable "sso_user_email" {
  description = "Email for SSO user assignment (optional)"
  type        = string
  default     = ""
}

variable "account_purpose" {
  description = "Purpose of the account"
  type        = string
  default     = "AFT management and account vending"
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

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (SOC 2: 7 years = 2555 days)"
  type        = number
  default     = 2555
}

variable "environment" {
  description = "Environment classification"
  type        = string
  default     = "management"
}

# Data source to get current AWS account context
data "aws_caller_identity" "current" {}

data "aws_organization" "org" {}

# AFT Account Request Module
# Official AWS module for account vending via Control Tower
module "aft_account_request" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory//modules/aft-account-request"

  # Control Tower account parameters
  control_tower_parameters = {
    AccountEmail              = var.account_email
    AccountName               = var.account_name
    ManagedOrganizationalUnit = var.managed_organizational_unit
    SSOUserEmail              = var.sso_user_email != "" ? var.sso_user_email : null
  }

  # Account tags for metadata and compliance tracking
  account_tags = {
    Environment  = var.environment
    Purpose      = var.account_purpose
    ManagedBy    = "CARL"
    Compliance   = "SOC2TypeII"
    CreatedDate  = formatdate("YYYY-MM-DD", timestamp())
    CostCenter   = "Infrastructure"
    DataClass    = "Confidential"
  }

  # Change management parameters for audit trail (SOC 2 requirement)
  change_management_parameters = {
    change_requested_by = "CARL-AFT-Framework"
    change_reason       = "Automated account provisioning via AFT"
  }

  # Custom fields to trigger security service enablement
  custom_fields = {
    enable_guardduty    = var.enable_guardduty
    enable_security_hub = var.enable_security_hub
    enable_config       = var.enable_config
  }

  # Select account customization based on OU
  account_customizations_name = "shared-services-security"
}

# CloudWatch Log Group for AFT operations (SOC 2: Logging and Audit Trail)
resource "aws_cloudwatch_log_group" "aft_operations" {
  name              = "/aws/aft/account-requests/${var.account_name}"
  retention_in_days = var.log_retention_days

  kms_key_id = aws_kms_key.aft_logs.arn

  tags = {
    Name        = "aft-operations-logs"
    Purpose     = "AFT account request audit trail"
    Compliance  = "SOC2TypeII"
    ManagedBy   = "CARL"
  }
}

# KMS Key for CloudWatch Logs encryption (SOC 2: Encryption at Rest)
resource "aws_kms_key" "aft_logs" {
  description             = "KMS key for AFT operations logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name       = "aft-logs-key"
    ManagedBy  = "CARL"
    Compliance = "SOC2TypeII"
  }
}

resource "aws_kms_alias" "aft_logs" {
  name          = "alias/aft-operations-logs"
  target_key_id = aws_kms_key.aft_logs.key_id
}

# SNS Topic for AFT notifications (SOC 2: Monitoring and Alerting)
resource "aws_sns_topic" "aft_notifications" {
  name              = "aft-account-request-notifications"
  kms_master_key_id = aws_kms_key.aft_logs.id

  tags = {
    Name       = "aft-notifications"
    ManagedBy  = "CARL"
    Compliance = "SOC2TypeII"
  }
}

resource "aws_sns_topic_policy" "aft_notifications" {
  arn = aws_sns_topic.aft_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAFTPublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.aft_notifications.arn
      }
    ]
  })
}

# EventBridge Rule to capture AFT account creation events (SOC 2: Audit Trail)
resource "aws_cloudwatch_event_rule" "aft_account_creation" {
  name        = "aft-account-creation-events"
  description = "Capture AFT account creation events for audit trail"

  event_pattern = jsonencode({
    source      = ["aws.controltower"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateManagedAccount"]
    }
  })

  tags = {
    Name       = "aft-account-creation-rule"
    ManagedBy  = "CARL"
    Compliance = "SOC2TypeII"
  }
}

resource "aws_cloudwatch_event_target" "aft_account_creation_sns" {
  rule      = aws_cloudwatch_event_rule.aft_account_creation.name
  target_id = "AFTAccountCreationNotification"
  arn       = aws_sns_topic.aft_notifications.arn

  input_transformer = {
    input_paths = {
      account = "$.detail.requestParameters.accountName"
      email   = "$.detail.requestParameters.accountEmail"
      time    = "$.time"
    }
    input_template = "\"AFT Account Request: <account> (<email>) created at <time>\""
  }
}

# CloudTrail for AFT operations audit (SOC 2: Logging and Compliance)
resource "aws_cloudtrail" "aft_operations" {
  name                          = "aft-operations-trail"
  s3_bucket_name                = aws_s3_bucket.aft_cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.aft_cloudtrail_logs]

  kms_key_id = "${aws_kms_key.aft_logs.arn}:alias/aft-operations-logs"

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }

  tags = {
    Name       = "aft-operations-trail"
    ManagedBy  = "CARL"
    Compliance = "SOC2TypeII"
  }
}

# S3 Bucket for CloudTrail logs (SOC 2: Encryption and Audit Trail)
resource "aws_s3_bucket" "aft_cloudtrail_logs" {
  bucket = "aft-cloudtrail-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name       = "aft-cloudtrail-logs"
    ManagedBy  = "CARL"
    Compliance = "SOC2TypeII"
  }
}

resource "aws_s3_bucket_versioning" "aft_cloudtrail_logs" {
  bucket = aws_s3_bucket.aft_cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aft_cloudtrail_logs" {
  bucket = aws_s3_bucket.aft_cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.aft_logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "aft_cloudtrail_logs" {
  bucket = aws_s3_bucket.aft_cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "aft_cloudtrail_logs" {
  bucket = aws_s3_bucket.aft_cloudtrail_logs.id

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
        Resource = aws_s3_bucket.aft_cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.aft_cloudtrail_logs.arn}/*"
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
        Resource = "${aws_s3_bucket.aft_cloudtrail_logs.arn}/*"
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
          aws_s3_bucket.aft_cloudtrail_logs.arn,
          "${aws_s3_bucket.aft_cloudtrail_logs.arn}/*"
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

# S3 Lifecycle policy for log retention (SOC 2: 7-year retention)
resource "aws_s3_bucket_lifecycle_configuration" "aft_cloudtrail_logs" {
  bucket = aws_s3_bucket.aft_cloudtrail_logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555
    }
  }
}

# IAM Role for AFT account customization (SOC 2: Least Privilege)
resource "aws_iam_role" "aft_account_customization" {
  name = "aft-account-customization-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name       = "aft-account-customization-role"
    ManagedBy  = "CARL"
    Compliance = "SOC2TypeII"
  }
}

resource "aws_iam_role_policy" "aft_account_customization" {
  name = "aft-account-customization-policy"
  role = aws_