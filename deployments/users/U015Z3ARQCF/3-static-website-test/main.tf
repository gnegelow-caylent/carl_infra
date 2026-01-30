```hcl
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  name_prefix = "test"
  environment = "dev"
  project     = "static-websites"

  common_tags = {
    Name      = local.name_prefix
    Environment = local.environment
    ManagedBy = "Terraform"
    Project   = local.project
  }

  websites = {
    site1 = {
      domain_name = "site1.example.com"
      index_doc   = "index.html"
      error_doc   = "error.html"
    }
    site2 = {
      domain_name = "site2.example.com"
      index_doc   = "index.html"
      error_doc   = "error.html"
    }
    site3 = {
      domain_name = "site3.example.com"
      index_doc   = "index.html"
      error_doc   = "error.html"
    }
  }
}

# ============================================================================
# KMS Key for S3 Encryption (SOC 2: CC6.6, CC6.7 - Encryption at Rest)
# ============================================================================
resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 static website encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-s3-key"
    }
  )
}

resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/${local.name_prefix}-s3-encryption"
  target_key_id = aws_kms_key.s3_key.key_id
}

# ============================================================================
# S3 Buckets for Static Websites (Private, Encrypted)
# ============================================================================
resource "aws_s3_bucket" "website_buckets" {
  for_each = local.websites

  bucket = "${local.name_prefix}-${each.key}-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-${each.key}-bucket"
    }
  )

  lifecycle {
    prevent_destroy = true
  }
}

# Block all public access to S3 buckets (SOC 2: CC6.1 - Access Control)
resource "aws_s3_bucket_public_access_block" "website_buckets" {
  for_each = aws_s3_bucket.website_buckets

  bucket = each.value.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for rollback capability
resource "aws_s3_bucket_versioning" "website_buckets" {
  for_each = aws_s3_bucket.website_buckets

  bucket = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption with KMS (SOC 2: CC6.6, CC6.7)
resource "aws_s3_bucket_server_side_encryption_configuration" "website_buckets" {
  for_each = aws_s3_bucket.website_buckets

  bucket = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

# Enable S3 access logging (SOC 2: CC7.2 - System Monitoring)
resource "aws_s3_bucket" "access_logs_bucket" {
  bucket = "${local.name_prefix}-access-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-access-logs-bucket"
    }
  )

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs_bucket" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_bucket" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "website_buckets" {
  for_each = aws_s3_bucket.website_buckets

  bucket = each.value.id

  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "${each.key}/"
}

# ============================================================================
# CloudFront Origin Access Identity (OAI) for Secure S3 Access
# ============================================================================
resource "aws_cloudfront_origin_access_identity" "oai" {
  for_each = local.websites

  comment = "OAI for ${each.key}"
}

# ============================================================================
# S3 Bucket Policies - Allow CloudFront OAI Access Only
# ============================================================================
resource "aws_s3_bucket_policy" "website_buckets" {
  for_each = aws_s3_bucket.website_buckets

  bucket = each.value.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOAI"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.oai[each.key].iam_arn
        }
        Action   = "s3:GetObject"
        Resource = "${each.value.arn}/*"
      },
      {
        Sid    = "AllowListBucket"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.oai[each.key].iam_arn
        }
        Action   = "s3:ListBucket"
        Resource = each.value.arn
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.website_buckets]
}

# ============================================================================
# ACM Certificates for HTTPS (SOC 2: CC6.2 - Encryption in Transit)
# ============================================================================
resource "aws_acm_certificate" "website_certs" {
  for_each = local.websites

  domain_name       = each.value.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-${each.key}-cert"
    }
  )
}

# ============================================================================
# WAF Web ACL for CloudFront (SOC 2: CC6.1 - Access Control)
# ============================================================================
resource "aws_wafv2_web_acl" "cloudfront_waf" {
  name  = "${local.name_prefix}-cloudfront-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-waf-metrics"
    sampled_requests_enabled   = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-cloudfront-waf"
    }
  )
}

# ============================================================================
# CloudFront Distributions with CDN, HTTPS, and WAF
# ============================================================================
resource "aws_cloudfront_distribution" "website_distributions" {
  for_each = local.websites

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = each.value.index_doc
  http_version        = "http2and3"

  # Origin configuration pointing to S3
  origin {
    domain_name = aws_s3_bucket.website_buckets[each.key].bucket_regional_domain_name
    origin_id   = "S3-${each.key}"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai[each.key].cloudfront_access_identity_path
    }
  }

  # Default cache behavior
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${each.key}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
  }

  # Cache behavior for static assets with longer TTL
  cache_behavior {
    path_pattern     = "/assets/*"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${each.key}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
  }

  # Custom error responses
  custom_error_response {
    error_code            = 404
    error_caching_min_ttl = 300
    response_code         = 404
    response_page_path    = "/${each.value.error_doc}"
  }

  custom_error_response {
    error_code            = 403
    error_caching_min_ttl = 300
    response_code         = 403
    response_page_path    = "/${each.value.error_doc}"
  }

  # HTTPS certificate
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.website_certs[each.key].arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # Aliases for custom domain
  aliases = [each.value.domain_name]

  # WAF integration
  web_acl_id = aws_wafv2_web_acl.cloudfront_waf.arn

  # Logging configuration
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.access_logs_bucket.bucket_regional_domain_name
    prefix          = "cloudfront/${each.key}/"
  }

  # Security headers
  http_version = "http2and3"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-${each.key}-distribution"
    }
  )

  depends_on = [aws_acm_certificate.website_certs]
}

# ============================================================================
# CloudWatch Alarms for Monitoring (SOC 2: CC7.2 - System Monitoring)
# ============================================================================
resource "aws_cloudwatch_metric_alarm" "cloudfront_4xx_errors" {
  for_each = aws_cloudfront_distribution.website_distributions

  alarm_name          = "${local.name_prefix}-${each.key}-4xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "4xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 5
  alarm_description   = "Alert when 4xx error rate exceeds 5%"
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = each.value.id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "cloudfront_5xx_errors" {
  for_each = aws_cloudfront_distribution.website_distributions

  alarm_name          = "${local.name_prefix}-${each.key}-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alert when 5xx error rate exceeds 1%"
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = each.value.id
  }

  tags = local.common_tags
}

# ============================================================================
# CloudTrail for Audit Logging (SOC 2: CC6.1, CC7.2 - Access Audit)
# ============================================================================
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.name_prefix}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-logs"
    }
  )

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
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

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-cloudtrail"
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
      values = ["arn:aws:s3:::${local.name_prefix}-*/*"]
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-cloudtrail"
    }
  )
}

# ============================================================================
# Data Sources
# ============================================================================
data "aws_caller_identity" "current" {}

# ============================================================================
# Outputs
# ============================================================================
output "cloudfront_distribution_ids" {
  description = "CloudFront distribution IDs for all websites"
  value = {
    for key, dist in aws_cloudfront_distribution.website_distributions :
    key => dist.id
  }
}

output "cloudfront_domain_names" {
  description = "CloudFront domain names for all websites"
  value = {
    for key, dist in aws_cloudfront_distribution.website_distributions :
    key => dist.domain_name
  }
}

output "s3_bucket_names" {
  description = "S3 bucket names for all websites"
  value = {
    for key, bucket in aws_s3_bucket.website_buckets :
    key => bucket.id
  }
}

output "acm_certificate_arns" {
  description = "ACM certificate ARNs for all websites"
  value = {
    for key, cert in aws_acm_certificate.website_certs :
    key => cert.arn
  }
}

output "waf_web_acl_arn" {
  description = "WAF Web ACL ARN for CloudFront"
  value       = aws_wafv2_web_acl.cloudfront_waf.arn
}

output "cloudtrail_name" {
  description = "CloudTrail name for audit logging"
  value       = aws_cloudtrail.main.name
}

output "kms_key_id" {
  description = "KMS key ID for S3 encryption"
  value       = aws_kms_key.s3_key.id
}
```