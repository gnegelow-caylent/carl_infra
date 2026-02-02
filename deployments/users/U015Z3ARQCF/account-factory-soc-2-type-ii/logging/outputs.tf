# Logging Module Outputs

output "cloudtrail_arn" {
  description = "CloudTrail trail ARN"
  value       = try(aws_cloudtrail.organization.arn, null)
}

output "central_logging_bucket_name" {
  description = "Central logging S3 bucket name"
  value       = try(aws_s3_bucket.central_logs.id, null)
}

output "cloudtrail_log_group_arn" {
  description = "CloudWatch Logs group ARN for CloudTrail"
  value       = try(aws_cloudwatch_log_group.cloudtrail.arn, null)
}
