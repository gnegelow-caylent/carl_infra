# CloudWatch Alarms for SOC 2 Type II Compliance
# Implements monitoring for critical security events per CIS AWS Foundations Benchmark
# Sends alerts to SNS topic for immediate notification

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
      CreatedAt  = timestamp()
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cloudtrail_log_group_name" {
  description = "CloudTrail CloudWatch Log Group name"
  type        = string
  default     = "/aws/cloudtrail/organization"
}

variable "sns_topic_name" {
  description = "SNS topic name for security alerts"
  type        = string
  default     = "security-alerts"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (SOC 2 requires 7 years minimum)"
  type        = number
  default     = 2555
}

variable "alarm_actions_enabled" {
  description = "Enable alarm actions"
  type        = bool
  default     = true
}

variable "treat_missing_data" {
  description = "How to treat missing data"
  type        = string
  default     = "notBreaching"
}

# Data source for existing SNS topic
data "aws_sns_topic" "security_alerts" {
  name = var.sns_topic_name
}

# Metric Filter: Root Account Usage (CIS 3.3)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = var.cloudtrail_log_group_name
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "cloudtrail-logs"
    Description = "CloudTrail logs for SOC 2 compliance"
  }
}

resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "RootAccountUsageMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsageCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "root_account_usage" {
  alarm_name          = "root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsageCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert when root account is used - CIS 3.3"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.3"
    SOC2       = "CC7.1"
  }
}

# Metric Filter: Unauthorized API Calls (CIS 3.1)
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "UnauthorizedAPICallsMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICallsCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "unauthorized_api_calls" {
  alarm_name          = "unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICallsCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on unauthorized API calls - CIS 3.1"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.1"
    SOC2       = "CC7.2"
  }
}

# Metric Filter: Console Login Without MFA (CIS 3.2)
resource "aws_cloudwatch_log_metric_filter" "console_login_without_mfa" {
  name           = "ConsoleLoginWithoutMFAMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"true\") }"

  metric_transformation {
    name      = "ConsoleLoginWithoutMFACount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "console_login_without_mfa" {
  alarm_name          = "console-login-without-mfa"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginWithoutMFACount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on console login without MFA - CIS 3.2"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.2"
    SOC2       = "CC6.1"
  }
}

# Metric Filter: IAM Policy Changes (CIS 3.4)
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "IAMPolicyChangesMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"

  metric_transformation {
    name      = "IAMPolicyChangesCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "iam_policy_changes" {
  alarm_name          = "iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChangesCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on IAM policy changes - CIS 3.4"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.4"
    SOC2       = "CC6.2"
  }
}

# Metric Filter: CloudTrail Configuration Changes (CIS 3.5)
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "CloudTrailChangesMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"

  metric_transformation {
    name      = "CloudTrailChangesCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "cloudtrail_changes" {
  alarm_name          = "cloudtrail-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailChangesCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on CloudTrail configuration changes - CIS 3.5"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.5"
    SOC2       = "CC7.1"
  }
}

# Metric Filter: Security Group Changes (CIS 3.10)
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "SecurityGroupChangesMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"

  metric_transformation {
    name      = "SecurityGroupChangesCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "security_group_changes" {
  alarm_name          = "security-group-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupChangesCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on security group changes - CIS 3.10"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.10"
    SOC2       = "CC6.1"
  }
}

# Metric Filter: Network ACL Changes (CIS 3.11)
resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  name           = "NACLChangesMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"

  metric_transformation {
    name      = "NACLChangesCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "nacl_changes" {
  alarm_name          = "nacl-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "NACLChangesCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on Network ACL changes - CIS 3.11"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.11"
    SOC2       = "CC6.1"
  }
}

# Metric Filter: KMS Key Changes (CIS 3.7)
resource "aws_cloudwatch_log_metric_filter" "kms_key_changes" {
  name           = "KMSKeyChangesMetricFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion) || ($.eventName = DeleteKey) }"

  metric_transformation {
    name      = "KMSKeyChangesCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "kms_key_changes" {
  alarm_name          = "kms-key-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "KMSKeyChangesCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on KMS key disabled or deleted - CIS 3.7"
  treat_missing_data  = var.treat_missing_data
  alarm_actions       = var.alarm_actions_enabled ? [data.aws_sns_topic.security_alerts.arn] : []

  tags = {
    CISControl = "3.7"
    SOC2       = "CC6.1"
  }
}

# Outputs
output "cloudtrail_log_group_name" {
  description = "CloudTrail CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudtrail_log_group_arn" {
  description = "CloudTrail CloudWatch Log Group ARN"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "alarm_names" {
  description = "List of all CloudWatch alarm names"
  value = [
    aws_cloudwatch_alarm.root_account_usage.alarm_name,
    aws_cloudwatch_alarm.unauthorized_api_calls.alarm_name,
    aws_cloudwatch_alarm.console_login_without_mfa.alarm_name,
    aws_cloudwatch_alarm.iam_policy_changes.alarm_name,
    aws_cloudwatch_alarm.cloudtrail_changes.alarm_name,
    aws_cloudwatch_alarm.security_group_changes