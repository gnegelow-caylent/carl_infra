```hcl
# ============================================================================
# TERRAFORM CONFIGURATION & PROVIDERS
# ============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # TODO: Configure remote state backend (S3 + DynamoDB for locking)
  # backend "s3" {
  #   bucket         = "terraform-state-bucket"
  #   key            = "static-websites/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      var.tags,
      {
        Environment = var.environment
        Project     = var.project_name
        ManagedBy   = "Terraform"
        CreatedAt   = timestamp()
      }
    )
  }
}

# ============================================================================
# LOCAL VALUES
# ============================================================================

locals {
  # Naming convention for all resources
  name_prefix = "${var.resource_prefix}-${var.environment}"

  # Common tags for all resources
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
    }
  )

  # CloudFront OAI (Origin Access Identity) for S3 access
  cloudfront_oai_comment = "OAI for ${local.name_prefix} static websites"

  # Logging bucket name (centralized logs for all sites)
  logging_bucket_name = "${local.name_prefix}-logs-${data.aws_caller_identity.current.account_id}"

  # WAF Web ACL name
  waf_web_acl_name = "${local.name_prefix}-waf"
}

# ============================================================================
# DATA SOURCES
# ============================================================================

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Get current AWS region
data "aws_region" "current" {}

# ============================================================================
# KMS KEY FOR ENCRYPTION
# ============================================================================

# KMS key for encrypting S3 buckets and CloudFront logs
resource "aws_kms_key" "s3_encryption" {
  count                   = var.enable_kms_encryption ? 1 : 0
  description             = "KMS key for encrypting S3 buckets and CloudFront logs - ${local.name_prefix}"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = var.kms_enable_key_rotation

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-s3-encryption-key"
    }
  )
}

resource "aws_kms_alias" "s3_encryption" {
  count         = var.enable_kms_encryption ? 1 : 0
  name          = "alias/${local.name_prefix}-s3-encryption"
  target_key_id = aws_kms_key.s3_encryption[0].key_id
}

# KMS key policy to allow CloudFront and S3 to use the key