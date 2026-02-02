# Security Baseline Outputs

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = try(aws_guardduty_detector.main.id, null)
}

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = try(aws_securityhub_account.main.arn, null)
}

output "config_recorder_name" {
  description = "AWS Config recorder name"
  value       = try(aws_config_configuration_recorder.main.name, null)
}
