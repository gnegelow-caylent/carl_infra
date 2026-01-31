```hcl
output "iot_core_endpoint" {
  description = "AWS IoT Core endpoint for MQTT/HTTPS connections"
  value       = aws_iot_endpoint.core.endpoint_address
}

output "iot_core_arn" {
  description = "ARN of the AWS IoT Core endpoint"
  value       = "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:client/$${iot:Connection.Thing.ThingName}"
}

output "iot_thing_group_arn" {
  description = "ARN of the IoT Thing Group"
  value       = aws_iot_thing_group.devices.arn
}

output "iot_policy_arn" {
  description = "ARN of the IoT device policy"
  value       = aws_iot_policy.device_policy.arn
}

output "iot_ca_certificate_arn" {
  description = "ARN of the IoT CA certificate"
  value       = aws_iot_certificate.ca.arn
}

output "lambda_processor_function_arn" {
  description = "ARN of the Lambda function for IoT message processing"
  value       = aws_lambda_function.iot_processor.arn
}

output "lambda_processor_function_name" {
  description = "Name of the Lambda function for IoT message processing"
  value       = aws_lambda_function.iot_processor.function_name
}

output "lambda_processor_role_arn" {
  description = "ARN of the IAM role for Lambda processor"
  value       = aws_iam_role.lambda_processor_role.arn
}

output "iot_rule_arn" {
  description = "ARN of the IoT Rule for message routing"
  value       = aws_iot_topic_rule.telemetry_rule.arn
}

output "iot_rule_name" {
  description = "Name of the IoT Rule for message routing"
  value       = aws_iot_topic_rule.telemetry_rule.name
}

output "dynamodb_device_state_table_name" {
  description = "Name of the DynamoDB table for device state"
  value       = aws_dynamodb_table.device_state.name
}

output "dynamodb_device_state_table_arn" {
  description = "ARN of the DynamoDB table for device state"
  value       = aws_dynamodb_table.device_state.arn
}

output "dynamodb_device_state_stream_arn" {
  description = "ARN of the DynamoDB Streams for device state table"
  value       = aws_dynamodb_table.device_state.stream_arn
}

output "s3_historical_data_bucket_name" {
  description = "Name of the S3 bucket for historical IoT data"
  value       = aws_s3_bucket.historical_data.id
}

output "s3_historical_data_bucket_arn" {
  description = "ARN of the S3 bucket for historical IoT data"
  value       = aws_s3_bucket.historical_data.arn
}

output "s3_historical_data_bucket_regional_domain_name" {
  description = "Regional domain name of the S3 bucket for historical data"
  value       = aws_s3_bucket.historical_data.bucket_regional_domain_name
}

output "kms_key_id" {
  description = "ID of the KMS key for encryption at rest"
  value       = aws_kms_key.iot_key.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key for encryption at rest"
  value       = aws_kms_key.iot_key.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS key"
  value       = aws_kms_alias.iot_key_alias.name
}

output "cloudwatch_log_group_iot_name" {
  description = "Name of the CloudWatch Log Group for IoT Core"
  value       = aws_cloudwatch_log_group.iot_core_logs.name
}

output "cloudwatch_log_group_iot_arn" {
  description = "ARN of the CloudWatch Log Group for IoT Core"
  value       = aws_cloudwatch_log_group.iot_core_logs.arn
}

output "cloudwatch_log_group_lambda_name" {
  description = "Name of the CloudWatch Log Group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "cloudwatch_log_group_lambda_arn" {
  description = "ARN of the CloudWatch Log Group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.arn
}

output "cloudwatch_metric_alarm_lambda_errors_arn" {
  description = "ARN of the CloudWatch alarm for Lambda errors"
  value       = aws_cloudwatch_metric_alarm.lambda_errors.arn
}

output "cloudwatch_metric_alarm_lambda_errors_name" {
  description = "Name of the CloudWatch alarm for Lambda errors"
  value       = aws_cloudwatch_metric_alarm.lambda_errors.alarm_name
}

output "cloudwatch_metric_alarm_iot_publish_in_arn" {
  description = "ARN of the CloudWatch alarm for IoT publish in metrics"
  value       = aws_cloudwatch_metric_alarm.iot_publish_in.arn
}

output "cloudwatch_metric_alarm_iot_publish_in_name" {
  description = "Name of the CloudWatch alarm for IoT publish in metrics"
  value       = aws_cloudwatch_metric_alarm.iot_publish_in.alarm_name
}

output "sns_topic_alerts_arn" {
  description = "ARN of the SNS topic for CloudWatch alarms"
  value       = aws_sns_topic.alerts.arn
}

output "sns_topic_alerts_name" {
  description = "Name of the SNS topic for CloudWatch alarms"
  value       = aws_sns_topic.alerts.name
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail for audit logging"
  value       = aws_cloudtrail.iot_audit.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail for audit logging"
  value       = aws_cloudtrail.iot_audit.arn
}

output "cloudtrail_s3_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.iot.id
}

output "guardduty_detector_arn" {
  description = "ARN of the GuardDuty detector"
  value       = aws_guardduty_detector.iot.arn
}

output "iam_role_iot_service_role_arn" {
  description = "ARN of the IAM role for IoT service"
  value       = aws_iam_role.iot_service_role.arn
}

output "iam_role_iot_service_role_name" {
  description = "Name of the IAM role for IoT service"
  value       = aws_iam_role.iot_service_role.name
}

output "iam_policy_iot_service_policy_arn" {
  description = "ARN of the IAM policy for IoT service"
  value       = aws_iam_role_policy.iot_service_policy.id
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "resource_prefix