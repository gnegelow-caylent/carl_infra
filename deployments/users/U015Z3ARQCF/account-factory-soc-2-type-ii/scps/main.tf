# SOC 2 Type II Consolidated Service Control Policies (SCPs)
# This module implements comprehensive SCPs to enforce SOC 2 compliance controls
# across AWS Organizations, including security service protection, encryption
# requirements, access controls, and infrastructure protection.

terraform {
  required_version = ">= 1.5"
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
      Module     = "scp-consolidated"
      CreatedAt  = timestamp()
    }
  }
}

# Variables for configuration
variable "aws_region" {
  description = "AWS region for provider"
  type        = string
  default     = "us-east-1"
}

variable "organization_root_id" {
  description = "AWS Organizations root ID"
  type        = string
}

variable "target_ou_ids" {
  description = "Map of OU names to their IDs for SCP attachment"
  type        = map(string)
  default     = {}
}

variable "approved_regions" {
  description = "List of approved AWS regions"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

variable "enable_scp_attachment" {
  description = "Enable automatic SCP attachment to OUs"
  type        = bool
  default     = false
}

# Local variables for SCP policy documents
locals {
  common_tags = {
    ManagedBy  = "CARL"
    Compliance = "SOC2-Type-II"
  }

  scps = {
    "deny-security-service-disable" = {
      description = "Prevent disabling security services (CC7.1, CC7.2)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenySecurityServiceDisable"
            Effect = "Deny"
            Action = [
              "guardduty:DeleteDetector",
              "guardduty:DisassociateFromMasterAccount",
              "guardduty:UpdateDetector",
              "securityhub:DisableSecurityHub",
              "securityhub:DeleteMembers",
              "securityhub:DisassociateFromMasterAccount",
              "config:DeleteConfigurationRecorder",
              "config:StopConfigurationRecorder",
              "config:DeleteDeliveryChannel",
              "cloudtrail:DeleteTrail",
              "cloudtrail:StopLogging",
              "cloudtrail:UpdateTrail",
              "access-analyzer:DeleteAnalyzer",
              "macie2:DisableMacie",
              "inspector2:Disable"
            ]
            Resource = "*"
          }
        ]
      })
      target_ous = []
    }

    "deny-root-user" = {
      description = "Deny root user actions except for billing (CC6.1)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenyRootUserActions"
            Effect = "Deny"
            NotAction = [
              "aws-portal:*",
              "budgets:*"
            ]
            Resource = "*"
            Condition = {
              StringLike = {
                "aws:PrincipalArn" = "arn:aws:iam::*:root"
              }
            }
          }
        ]
      })
      target_ous = []
    }

    "require-imdsv2" = {
      description = "Require IMDSv2 for EC2 instances (CC6.1)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "RequireIMDSv2"
            Effect = "Deny"
            Action = [
              "ec2:RunInstances"
            ]
            Resource = "arn:aws:ec2:*:*:instance/*"
            Condition = {
              StringNotEquals = {
                "ec2:MetadataHttpTokens" = "required"
              }
            }
          }
        ]
      })
      target_ous = []
    }

    "require-encryption" = {
      description = "Require encryption for S3, EBS, RDS (CC6.1, C1.1)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenyUnencryptedS3Upload"
            Effect = "Deny"
            Action = [
              "s3:PutObject"
            ]
            Resource = "*"
            Condition = {
              Null = {
                "s3:x-amz-server-side-encryption" = "true"
              }
            }
          },
          {
            Sid    = "DenyUnencryptedEBS"
            Effect = "Deny"
            Action = [
              "ec2:RunInstances"
            ]
            Resource = "arn:aws:ec2:*:*:volume/*"
            Condition = {
              Bool = {
                "ec2:Encrypted" = "false"
              }
            }
          },
          {
            Sid    = "DenyUnencryptedRDS"
            Effect = "Deny"
            Action = [
              "rds:CreateDBInstance",
              "rds:CreateDBCluster"
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
      target_ous = []
    }

    "require-ssl-s3" = {
      description = "Require SSL/TLS for S3 access (CC6.7)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenyInsecureS3Transport"
            Effect = "Deny"
            Action = [
              "s3:*"
            ]
            Resource = "*"
            Condition = {
              Bool = {
                "aws:SecureTransport" = "false"
              }
            }
          }
        ]
      })
      target_ous = []
    }

    "deny-public-s3" = {
      description = "Deny public S3 buckets (CC6.1)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenyPublicS3Access"
            Effect = "Deny"
            Action = [
              "s3:PutBucketPublicAccessBlock",
              "s3:DeletePublicAccessBlock"
            ]
            Resource = "*"
          }
        ]
      })
      target_ous = []
    }

    "deny-leave-organization" = {
      description = "Prevent accounts from leaving organization (CC6.1)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenyLeaveOrganization"
            Effect = "Deny"
            Action = [
              "organizations:LeaveOrganization"
            ]
            Resource = "*"
          }
        ]
      })
      target_ous = []
    }

    "restrict-regions" = {
      description = "Restrict to approved regions only (CC6.6)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "RestrictToApprovedRegions"
            Effect = "Deny"
            NotAction = [
              "cloudfront:*",
              "iam:*",
              "route53:*",
              "support:*",
              "budgets:*",
              "waf:*",
              "waf-regional:*",
              "cloudwatch:*",
              "sns:*",
              "sqs:*"
            ]
            Resource = "*"
            Condition = {
              StringNotEquals = {
                "aws:RequestedRegion" = var.approved_regions
              }
            }
          }
        ]
      })
      target_ous = []
    }

    "deny-vpc-changes" = {
      description = "Protect VPC infrastructure (CC6.6, CC8.1)"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "DenyVPCChanges"
            Effect = "Deny"
            Action = [
              "ec2:DeleteVpc",
              "ec2:DeleteSubnet",
              "ec2:DeleteInternetGateway",
              "ec2:DeleteNatGateway",
              "ec2:DeleteRouteTable",
              "ec2:DeleteFlowLogs"
            ]
            Resource = "*"
            Condition = {
              StringNotLike = {
                "aws:PrincipalArn" = [
                  "arn:aws:iam::*:role/AWSControlTowerExecution",
                  "arn:aws:iam::*:role/AWSAFTExecution"
                ]
              }
            }
          }
        ]
      })
      target_ous = []
    }
  }
}

# Create Service Control Policies
resource "aws_organizations_policy" "scp" {
  for_each = local.scps

  name            = each.key
  description     = each.value.description
  content         = each.value.policy
  type            = "SERVICE_CONTROL_POLICY"
  skip_destroy    = false

  tags = merge(
    local.common_tags,
    {
      Name = each.key
    }
  )
}

# Attach SCPs to organization root by default
resource "aws_organizations_policy_attachment" "scp_root" {
  for_each = var.enable_scp_attachment ? local.scps : {}

  policy_id = aws_organizations_policy.scp[each.key].id
  target_id = var.organization_root_id
}

# Attach SCPs to specific OUs if provided
resource "aws_organizations_policy_attachment" "scp_ou" {
  for_each = var.enable_scp_attachment ? {
    for pair in flatten([
      for scp_name, scp in local.scps : [
        for ou in scp.target_ous : {
          key       = "${scp_name}-${ou}"
          policy_id = aws_organizations_policy.scp[scp_name].id
          target_id = lookup(var.target_ou_ids, ou, null)
        }
      ] if length(scp.target_ous) > 0
    ]) : pair.key => pair if pair.target_id != null
  } : {}

  policy_id = each.value.policy_id
  target_id = each.value.target_id
}

# Outputs
output "scp_policies" {
  description = "Map of created SCP policy IDs and names"
  value = {
    for name, policy in aws_organizations_policy.scp : name => {
      id          = policy.id
      arn         = policy.arn
      name        = policy.name
      description = policy.description
    }
  }
}

output "scp_policy_ids" {
  description = "List of all created SCP policy IDs"
  value       = [for policy in aws_organizations_policy.scp : policy.id]
}

output "scp_count" {
  description = "Total number of SCPs created"
  value       = length(aws_organizations_policy.scp)
}

output "scp_attachment_count" {
  description = "Total number of SCP attachments"
  value       = length(aws_organizations_policy_attachment.scp_root) + length(aws_organizations_policy_attachment.scp_ou)
}

output "compliance_controls_mapped" {
  description = "SOC 2 compliance controls mapped by SCP"
  value = {
    "CC6.1" = [
      "deny-root-user",
      "require-imdsv2",
      "require-encryption",
      "deny-public-s3",
      "deny-leave-organization"
    ]
    "CC6.6" = [
      "restrict-regions",
      "deny-vpc-changes"
    ]
    "CC6.7" = [
      "require-ssl-s3"
    ]
    "CC7.1" = [
      "deny-security-service-disable"
    ]
    "CC7.2" = [
      "deny-security-service-disable"
    ]
    "CC8.1" = [
      "deny-vpc-changes"
    ]
    "C1.1" = [
      "require-encryption"
    ]
  }
}