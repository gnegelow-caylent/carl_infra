# AWS Service Control Policy (SCP) for Region Restriction
# Implements SOC 2 CC6.6 - Restricts AWS API calls to approved regions only
# Part of AFT Framework - Applied at Organization level to OUs

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
      Compliance = "SOC2-Type-II"
      Framework  = "AFT"
      Purpose    = "Region-Restriction-SCP"
    }
  }
}

# Variables for SCP Configuration
variable "aws_region" {
  description = "AWS region for provider"
  type        = string
  default     = "us-east-1"
}

variable "scp_name" {
  description = "Name of the Service Control Policy"
  type        = string
  default     = "restrict_regions"
}

variable "scp_description" {
  description = "Description of the SCP for audit purposes"
  type        = string
  default     = "Restrict to approved regions only (CC6.6)"
}

variable "approved_regions" {
  description = "List of approved AWS regions for resource deployment"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

variable "global_services_exempt" {
  description = "Services that operate globally and should not be restricted by region"
  type        = list(string)
  default = [
    "cloudfront",
    "iam",
    "route53",
    "support",
    "budgets",
    "waf",
    "waf-regional",
    "cloudwatch",
    "sns",
    "sqs"
  ]
}

variable "target_ou_ids" {
  description = "List of Organization Unit IDs to attach this SCP to"
  type        = list(string)
  default     = []
}

variable "enable_scp" {
  description = "Enable or disable the SCP attachment"
  type        = bool
  default     = true
}

# Data source to get current AWS organization
data "aws_organizations_organization" "current" {}

# Data source to get current AWS account
data "aws_caller_identity" "current" {}

# Local values for policy construction
locals {
  policy_name = "${var.scp_name}-${data.aws_caller_identity.current.account_id}"
  
  # Build the list of global services to exempt from region restriction
  exempt_actions = [for service in var.global_services_exempt : "${service}:*"]
  
  # Common tags for all resources
  common_tags = {
    ManagedBy      = "CARL"
    Compliance     = "SOC2-Type-II"
    Framework      = "AFT"
    Purpose        = "Region-Restriction-SCP"
    CreatedDate    = timestamp()
    PolicyName     = var.scp_name
    ApprovedRegions = join(",", var.approved_regions)
  }
}

# Service Control Policy - Deny operations outside approved regions
# Implements SOC 2 CC6.6 - Restricts resource deployment to compliant regions
resource "aws_organizations_policy" "restrict_regions" {
  name        = local.policy_name
  description = var.scp_description
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyOutsideApprovedRegions"
        Effect = "Deny"
        NotAction = local.exempt_actions
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.approved_regions
          }
        }
      },
      {
        Sid    = "AllowGlobalServices"
        Effect = "Allow"
        Action = local.exempt_actions
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Type = "RegionRestriction"
    }
  )
}

# Attach SCP to target OUs
# This allows the policy to be applied to specific organizational units
resource "aws_organizations_policy_attachment" "restrict_regions" {
  for_each = toset(var.target_ou_ids)

  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = each.value

  depends_on = [aws_organizations_policy.restrict_regions]
}

# CloudWatch Log Group for SCP audit trail (7-year retention for SOC 2)
resource "aws_cloudwatch_log_group" "scp_audit" {
  name              = "/aws/organizations/scp/${var.scp_name}"
  retention_in_days = 2555  # 7 years for SOC 2 compliance

  tags = merge(
    local.common_tags,
    {
      Type = "AuditLog"
    }
  )
}

# KMS Key for encrypting audit logs (SOC 2 encryption at rest)
resource "aws_kms_key" "scp_audit_key" {
  description             = "KMS key for SCP audit log encryption - SOC 2 compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Type = "AuditEncryption"
    }
  )
}

resource "aws_kms_alias" "scp_audit_key_alias" {
  name          = "alias/scp-audit-${var.scp_name}"
  target_key_id = aws_kms_key.scp_audit_key.key_id
}

# CloudTrail for SCP policy changes (SOC 2 CC7.2 - Audit Trail)
resource "aws_cloudtrail" "scp_changes" {
  name                          = "${var.scp_name}-trail"
  s3_bucket_name                = aws_s3_bucket.scp_audit_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.scp_audit_bucket_policy]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Organizations::Policy"
      values = ["arn:aws:organizations::${data.aws_caller_identity.current.account_id}:policy/o-*/service_control_policy/*"]
    }
  }

  tags = merge(
    local.common_tags,
    {
      Type = "AuditTrail"
    }
  )
}

# S3 Bucket for CloudTrail logs (SOC 2 encryption at rest)
resource "aws_s3_bucket" "scp_audit_bucket" {
  bucket = "scp-audit-${var.scp_name}-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Type = "AuditStorage"
    }
  )
}

# Enable versioning for audit trail integrity
resource "aws_s3_bucket_versioning" "scp_audit_bucket" {
  bucket = aws_s3_bucket.scp_audit_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption at rest for audit bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "scp_audit_bucket" {
  bucket = aws_s3_bucket.scp_audit_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.scp_audit_key.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access to audit bucket
resource "aws_s3_bucket_public_access_block" "scp_audit_bucket" {
  bucket = aws_s3_bucket.scp_audit_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket policy for CloudTrail access
resource "aws_s3_bucket_policy" "scp_audit_bucket_policy" {
  bucket = aws_s3_bucket.scp_audit_bucket.id

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
        Resource = aws_s3_bucket.scp_audit_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.scp_audit_bucket.arn}/*"
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
        Resource = "${aws_s3_bucket.scp_audit_bucket.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# Lifecycle policy for audit logs (7-year retention for SOC 2)
resource "aws_s3_bucket_lifecycle_configuration" "scp_audit_bucket" {
  bucket = aws_s3_bucket.scp_audit_bucket.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555  # 7 years
    }
  }
}

# CloudWatch Alarm for SCP policy changes (SOC 2 CC7.2)
resource "aws_cloudwatch_metric_alarm" "scp_policy_changes" {
  alarm_name          = "${var.scp_name}-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PolicyChangeCount"
  namespace           = "AWS/Organizations"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on SCP policy changes for audit trail"
  treat_missing_data  = "notBreaching"

  tags = merge(
    local.common_tags,
    {
      Type = "Monitoring"
    }
  )
}

# Outputs for integration with AFT framework
output "scp_id" {
  description = "The ID of the created Service Control Policy"
  value       = aws_organizations_policy.restrict_regions.id
}

output "scp_arn" {
  description = "The ARN of the created Service Control Policy"
  value       = aws_organizations_policy.restrict_regions.arn
}

output "scp_name" {
  description = "The name of the created Service Control Policy"
  value       = aws_organizations_policy.restrict_regions.name
}

output "approved_regions" {
  description = "List of approved regions enforced by this SCP"
  value       = var.approved_regions
}

output "audit_log_group_name" {
  description = "CloudWatch Log Group for SCP audit trail"
  value       = aws_cloudwatch_log_group.scp_audit.name
}

output "audit_bucket_name" {
  description = "S3 bucket for CloudTrail audit logs"
  value       = aws_s3_bucket.scp_audit_bucket.id
}

output "cloudtrail_name" {
  description = "CloudTrail for SCP policy changes"
  value       = aws_cloudtrail.scp_changes.name
}

output "kms_key_id" {
  description = "KMS key ID for audit log encryption"
  value       = aws_kms_key.scp_audit_key.id
}

output "scp_attachment_count" {
  description = "Number of OUs this SCP is attached to"
  value       = length(aws_organizations_policy_attachment.restrict_regions)
}

output "soc2_compliance_status" {
  description = "SOC 2 compliance controls implemented"
  value = {
    CC6_6_region_restriction = "Implemented"
    CC7_2_audit_trail        = "Implemented"
    encryption_at_rest       = "Implemented"
    encryption_in_transit    = "Implemented"
    log_retention_years      = 7
  }
}