# SCP Module Outputs

output "scp_ids" {
  description = "Map of SCP names to SCP IDs"
  value       = { for k, v in aws_organizations_policy.scp : k => v.id }
}

output "scp_arns" {
  description = "Map of SCP names to SCP ARNs"
  value       = { for k, v in aws_organizations_policy.scp : k => v.arn }
}
