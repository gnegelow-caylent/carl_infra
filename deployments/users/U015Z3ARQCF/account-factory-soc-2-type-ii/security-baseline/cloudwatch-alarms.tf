# CloudWatch Alarms for SOC 2 Type II Compliance
# Implements monitoring for security events per CIS AWS Foundations Benchmark
# Provides real-time alerting for unauthorized activities and configuration changes

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
}

# Variables
variable "aws_region" {
  description = "AWS region for resources"
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
  description = "CloudWatch Log retention in days (SOC 2 requires 7 years)"
  type        = number
  default     = 2555
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "security-monitoring"
}

variable "email_endpoints" {
  description = "Email addresses for SNS subscriptions"
  type        = list(string)
  default     = []
}

# Data source for existing CloudTrail log group
data "aws_cloudwatch_log_group" "cloudtrail" {
  name = var.cloudtrail_log_group_name
}

# SNS Topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name              = var.sns_topic_name
  kms_master_key_id = aws_kms_key.sns.id

  tags = {
    Name        = var.sns_topic_name
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
  }
}

# KMS Key for SNS encryption
resource "aws_kms_key" "sns" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-sns-key"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
  }
}

resource "aws_kms_alias" "sns" {
  name          = "alias/${var.project_name}-sns"
  target_key_id = aws_kms_key.sns.key_id
}

# SNS Topic Policy for CloudWatch Logs
resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Email subscriptions for SNS topic
resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.email_endpoints)

  topic_arn            = aws_sns_topic.security_alerts.arn
  protocol             = "email"
  endpoint             = each.value
  filter_policy_scope  = "MessageAttributes"
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# ============================================================================
# METRIC FILTERS AND ALARMS - CIS AWS Foundations Benchmark Compliance
# ============================================================================

# 1. Root Account Usage (CIS 3.3)
resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "RootAccountUsageFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsageMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsageMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert when root account is used - CIS 3.3"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "root-account-usage"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
    CIS         = "3.3"
  }
}

# 2. Unauthorized API Calls (CIS 3.1)
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "UnauthorizedAPICallsFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICallsMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICallsMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Alert on unauthorized API calls - CIS 3.1"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "unauthorized-api-calls"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
    CIS         = "3.1"
  }
}

# 3. Console Login Without MFA (CIS 3.2)
resource "aws_cloudwatch_log_metric_filter" "console_login_without_mfa" {
  name           = "ConsoleLoginWithoutMFAFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"true\") }"

  metric_transformation {
    name      = "ConsoleLoginWithoutMFAMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_login_without_mfa" {
  alarm_name          = "console-login-without-mfa"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginWithoutMFAMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on console login without MFA - CIS 3.2"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "console-login-without-mfa"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
    CIS         = "3.2"
  }
}

# 4. IAM Policy Changes (CIS 3.4)
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "IAMPolicyChangesFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }"

  metric_transformation {
    name      = "IAMPolicyChangesMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChangesMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on IAM policy changes - CIS 3.4"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "iam-policy-changes"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
    CIS         = "3.4"
  }
}

# 5. CloudTrail Configuration Changes (CIS 3.5)
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "CloudTrailChangesFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging) }"

  metric_transformation {
    name      = "CloudTrailChangesMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name          = "cloudtrail-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailChangesMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on CloudTrail configuration changes - CIS 3.5"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "cloudtrail-changes"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
    CIS         = "3.5"
  }
}

# 6. Security Group Changes (CIS 3.10)
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "SecurityGroupChangesFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup) }"

  metric_transformation {
    name      = "SecurityGroupChangesMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  alarm_name          = "security-group-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupChangesMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on security group changes - CIS 3.10"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "security-group-changes"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance  = "SOC2-TypeII"
    CIS         = "3.10"
  }
}

# 7. Network ACL Changes (CIS 3.11)
resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  name           = "NACLChangesFilter"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern = "{ ($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation) }"

  metric_transformation {
    name      = "NACLChangesMetric"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  alarm_name          = "nacl-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "NACLChangesMetric"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on network ACL changes - CIS 3.11"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "nacl-changes"
    Environment = var.environment
    ManagedBy   = "CARL"
    Compliance