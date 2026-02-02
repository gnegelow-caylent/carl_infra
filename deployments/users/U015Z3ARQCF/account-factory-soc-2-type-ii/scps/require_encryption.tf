# AWS Service Control Policy (SCP) for SOC 2 Type II Compliance
# Enforces encryption requirements for S3, EBS, and RDS
# Maps to SOC 2 CC6.1 (Logical and Physical Access Controls) and C1.1 (Information and Assets)
# Integrated with AWS Control Tower via AFT Framework

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
      Compliance = "SOC2-TypeII"
      Framework  = "AFT"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for SCP Configuration
variable "aws_region" {
  description = "AWS region for SCP deployment"
  type        = string
  default     = "us-east-1"
}

variable "scp_name" {
  description = "Name of the Service Control Policy"
  type        = string
  default     = "require_encryption"
}

variable "scp_description" {
  description = "Description of the SCP for SOC 2 compliance"
  type        = string
  default     = "Require encryption for S3, EBS, RDS (CC6.1, C1.1)"
}

variable "target_ou_ids" {
  description = "List of Organizational Unit IDs to attach the SCP"
  type        = list(string)
  default     = []
}

variable "enable_s3_encryption_enforcement" {
  description = "Enable S3 encryption enforcement"
  type        = bool
  default     = true
}

variable "enable_ebs_encryption_enforcement" {
  description = "Enable EBS encryption enforcement"
  type        = bool
  default     = true
}

variable "enable_rds_encryption_enforcement" {
  description = "Enable RDS encryption enforcement"
  type        = bool
  default     = true
}

variable "break_glass_principal_arns" {
  description = "Principal ARNs exempt from encryption requirements (break-glass access)"
  type        = list(string)
  default     = []
}

# Data source to get AWS Organization
data "aws_organizations_organization" "current" {}

# Data source to get current AWS account
data "aws_caller_identity" "current" {}

# S3 Encryption Enforcement SCP
resource "aws_organizations_policy" "require_s3_encryption" {
  count       = var.enable_s3_encryption_enforcement ? 1 : 0
  name        = "${var.scp_name}-s3-encryption"
  description = "Deny S3 PutObject without server-side encryption (SOC 2 CC6.1)"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedS3ObjectUpload"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObject"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = [
              "AES256",
              "aws:kms"
            ]
          }
        }
      },
      {
        Sid    = "DenyS3EncryptionWithoutKMS"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObject"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
          StringNotLike = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = [
              "arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.scp_name}-s3-encryption"
    Compliance  = "SOC2-TypeII"
    Control     = "CC6.1"
    Description = "S3 Encryption Enforcement"
  }
}

# EBS Encryption Enforcement SCP
resource "aws_organizations_policy" "require_ebs_encryption" {
  count       = var.enable_ebs_encryption_enforcement ? 1 : 0
  name        = "${var.scp_name}-ebs-encryption"
  description = "Deny EC2 RunInstances without EBS encryption (SOC 2 CC6.1)"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedEBSVolume"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:aws:ec2:*:*:volume/*"
        ]
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      },
      {
        Sid    = "DenyCreateUnencryptedVolume"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "ec2:CreateVolume"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.scp_name}-ebs-encryption"
    Compliance  = "SOC2-TypeII"
    Control     = "CC6.1"
    Description = "EBS Encryption Enforcement"
  }
}

# RDS Encryption Enforcement SCP
resource "aws_organizations_policy" "require_rds_encryption" {
  count       = var.enable_rds_encryption_enforcement ? 1 : 0
  name        = "${var.scp_name}-rds-encryption"
  description = "Deny RDS CreateDBInstance/Cluster without encryption (SOC 2 CC6.1)"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedRDSInstance"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "rds:CreateDBInstance"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedRDSCluster"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "rds:CreateDBCluster"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      },
      {
        Sid    = "DenyRDSEncryptionDisable"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "rds:ModifyDBInstance",
          "rds:ModifyDBCluster"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.scp_name}-rds-encryption"
    Compliance  = "SOC2-TypeII"
    Control     = "CC6.1"
    Description = "RDS Encryption Enforcement"
  }
}

# Attach S3 Encryption SCP to target OUs
resource "aws_organizations_policy_attachment" "s3_encryption_attachment" {
  for_each = toset(var.target_ou_ids)

  policy_id = aws_organizations_policy.require_s3_encryption[0].id
  target_id = each.value

  depends_on = [aws_organizations_policy.require_s3_encryption]
}

# Attach EBS Encryption SCP to target OUs
resource "aws_organizations_policy_attachment" "ebs_encryption_attachment" {
  for_each = toset(var.target_ou_ids)

  policy_id = aws_organizations_policy.require_ebs_encryption[0].id
  target_id = each.value

  depends_on = [aws_organizations_policy.require_ebs_encryption]
}

# Attach RDS Encryption SCP to target OUs
resource "aws_organizations_policy_attachment" "rds_encryption_attachment" {
  for_each = toset(var.target_ou_ids)

  policy_id = aws_organizations_policy.require_rds_encryption[0].id
  target_id = each.value

  depends_on = [aws_organizations_policy.require_rds_encryption]
}

# CloudTrail for SCP audit trail (7-year retention for SOC 2)
resource "aws_s3_bucket" "scp_audit_logs" {
  bucket = "scp-audit-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name        = "scp-audit-logs"
    Compliance  = "SOC2-TypeII"
    Purpose     = "SCP Audit Trail"
    Retention   = "7-years"
  }
}

resource "aws_s3_bucket_versioning" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "scp_audit_logs" {
  bucket = aws_s3_bucket.scp_audit_logs.id

  rule {
    id     = "archive-after-90-days"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years
    }
  }
}

# CloudWatch Log Group for SCP monitoring
resource "aws_cloudwatch_log_group" "scp_monitoring" {
  name              = "/aws/scp/encryption-enforcement"
  retention_in_days = 2555 # 7 years for SOC 2

  tags = {
    Name       = "scp-encryption-enforcement-logs"
    Compliance = "SOC2-TypeII"
    Purpose    = "SCP Monitoring and Audit"
  }
}

# Outputs
output "s3_encryption_scp_id" {
  description = "ID of the S3 encryption enforcement SCP"
  value       = try(aws_organizations_policy.require_s3_encryption[0].id, null)
}

output "ebs_encryption_scp_id" {
  description = "ID of the EBS encryption enforcement SCP"
  value       = try(aws_organizations_policy.require_ebs_encryption[0].id, null)
}

output "rds_encryption_scp_id" {
  description = "ID of the RDS encryption enforcement SCP"
  value       = try(aws_organizations_policy.require_rds_encryption[0].id, null)
}

output "audit_log_bucket_name" {
  description = "Name of the S3 bucket for SCP audit logs"
  value       = aws_s3_bucket.scp_audit_logs.id
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for SCP monitoring"
  value       = aws_cloudwatch_log_group.scp_monitoring.name
}

output "organization_id" {
  description = "AWS Organization ID"
  value       = data.aws_organizations_organization.current.id
}

output "scp_compliance_controls" {
  description = "SOC 2 compliance controls addressed by these SCPs"
  value = {
    CC6_1 = "Logical and Physical Access Controls - Encryption enforcement"
    C1_1  = "Information and Assets - Data protection through encryption"
  }
}