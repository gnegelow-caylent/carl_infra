```hcl
# S3 Buckets
output "s3_bucket_website_1_id" {
  description = "ID of the first S3 bucket for static website hosting"
  value       = aws_s3_bucket.website_1.id
}

output "s3_bucket_website_1_arn" {
  description = "ARN of the first S3 bucket"
  value       = aws_s3_bucket.website_1.arn
}

output "s3_bucket_website_1_regional_domain_name" {
  description = "Regional domain name of the first S3 bucket"
  value       = aws_s3_bucket.website_1.bucket_regional_domain_name
}

output "s3_bucket_website_2_id" {
  description = "ID of the second S3 bucket for static website hosting"
  value       = aws_s3_bucket.website_2.id
}

output "s3_bucket_website_2_arn" {
  description = "ARN of the second S3 bucket"
  value       = aws_s3_bucket.website_2.arn
}

output "s3_bucket_website_2_regional_domain_name" {
  description = "Regional domain name of the second S3 bucket"
  value       = aws_s3_bucket.website_2.bucket_regional_domain_name
}

output "s3_bucket_website_3_id" {
  description = "ID of the third S3 bucket for static website hosting"
  value       = aws_s3_bucket.website_3.id
}

output "s3_bucket_website_3_arn" {
  description = "ARN of the third S3 bucket"
  value       = aws_s3_bucket.website_3.arn
}

output "s3_bucket_website_3_regional_domain_name" {
  description = "Regional domain name of the third S3 bucket"
  value       = aws_s3_bucket.website_3.bucket_regional_domain_name
}

# CloudFront Distributions
output "cloudfront_distribution_website_1_id" {
  description = "ID of the CloudFront distribution for website 1"
  value       = aws_cloudfront_distribution.website_1.id
}

output "cloudfront_distribution_website_1_domain_name" {
  description = "Domain name of the CloudFront distribution for website 1"
  value       = aws_cloudfront_distribution.website_1.domain_name
}

output "cloudfront_distribution_website_1_arn" {
  description = "ARN of the CloudFront distribution for website 1"
  value       = aws_cloudfront_distribution.website_1.arn
}

output "cloudfront_distribution_website_1_hosted_zone_id" {
  description = "CloudFront hosted zone ID for website 1 (use with Route 53 alias records)"
  value       = aws_cloudfront_distribution.website_1.hosted_zone_id
}

output "cloudfront_distribution_website_2_id" {
  description = "ID of the CloudFront distribution for website 2"
  value       = aws_cloudfront_distribution.website_2.id
}

output "cloudfront_distribution_website_2_domain_name" {
  description = "Domain name of the CloudFront distribution for website 2"
  value       = aws_cloudfront_distribution.website_2.domain_name
}

output "cloudfront_distribution_website_2_arn" {
  description = "ARN of the CloudFront distribution for website 2"
  value       = aws_cloudfront_distribution.website_2.arn
}

output "cloudfront_distribution_website_2_hosted_zone_id" {
  description = "CloudFront hosted zone ID for website 2 (use with Route 53 alias records)"
  value       = aws_cloudfront_distribution.website_2.hosted_zone_id
}

output "cloudfront_distribution_website_3_id" {
  description = "ID of the CloudFront distribution for website 3"
  value       = aws_cloudfront_distribution.website_3.id
}

output "cloudfront_distribution_website_3_domain_name" {
  description = "Domain name of the CloudFront distribution for website 3"
  value       = aws_cloudfront_distribution.website_3.domain_name
}

output "cloudfront_distribution_website_3_arn" {
  description = "ARN of the CloudFront distribution for website 3"
  value       = aws_cloudfront_distribution.website_3.arn
}

output "cloudfront_distribution_website_3_hosted_zone_id" {
  description = "CloudFront hosted zone ID for website 3 (use with Route 53 alias records)"
  value       = aws_cloudfront_distribution.website_3.hosted_zone_id
}

# ACM Certificates
output "acm_certificate_website_1_arn" {
  description = "ARN of the ACM certificate for website 1"
  value       = aws_acm_certificate.website_1.arn
}

output "acm_certificate_website_1_domain_name" {
  description = "Domain name of the ACM certificate for website 1"
  value       = aws_acm_certificate.website_1.domain_name
}

output "acm_certificate_website_2_arn" {
  description = "ARN of the ACM certificate for website 2"
  value       = aws_acm_certificate.website_2.arn
}

output "acm_certificate_website_2_domain_name" {
  description = "Domain name of the ACM certificate for website 2"
  value       = aws_acm_certificate.website_2.domain_name
}

output "acm_certificate_website_3_arn" {
  description = "ARN of the ACM certificate for website 3"
  value       = aws_acm_certificate.website_3.arn
}

output "acm_certificate_website_3_domain_name" {
  description = "Domain name of the ACM certificate for website 3"
  value       = aws_acm_certificate.website_3.domain_name
}

# KMS Keys for S3 Encryption
output "kms_key_s3_id" {
  description = "ID of the KMS key used for S3 encryption"
  value       = aws_kms_key.s3_encryption.id
}

output "kms_key_s3_arn" {
  description = "ARN of the KMS key used for S3 encryption"
  value       = aws_kms_key.s3_encryption.arn
}

output "kms_key_alias_s3" {
  description = "Alias of the KMS key for S3 encryption"
  value       = aws_kms_alias.s3_encryption.name
}

# S3 Access Logging Buckets
output "s3_bucket_logging_id" {
  description = "ID of the S3 bucket used for access logging"
  value       = aws_s3_bucket.logging.id
}

output "s3_bucket_logging_arn" {
  description = "ARN of the S3 bucket used for access logging"
  value       = aws_s3_bucket.logging.arn
}

# CloudTrail
output "cloudtrail_name" {
  description = "Name of the CloudTrail for audit logging"
  value       = aws_cloudtrail.s3_audit.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = aws_cloudtrail.s3_audit.arn
}

output "cloudtrail_s3_bucket_id" {
  description = "ID of the S3 bucket used for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

# CloudWatch Log Groups
output "cloudwatch_log_group_cloudtrail" {
  description = "Name of the CloudWatch log group for CloudTrail"
  value       = aws_cloudwatch_log