# Global Customizations Outputs

output "iam_password_policy_applied" {
  description = "IAM password policy configuration status"
  value       = true
}

output "s3_public_access_blocked" {
  description = "S3 public access block status"
  value       = true
}
