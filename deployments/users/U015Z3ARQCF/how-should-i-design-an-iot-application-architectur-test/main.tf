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
  name_prefix = "${var.resource_prefix}-${var.environment}"
  common_tags = {
    Name      = local.name_prefix
    Environment = var.environment
    ManagedBy = "Terraform"
    Project   = "IoT-Application"
  }
}

# KMS Key for encryption at rest
resource "aws_kms_key" "iot" {
  description             = "KMS key for IoT application encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-key"
    }
  )
}

resource "aws_kms_alias" "iot" {
  name          = "alias/${local.name_prefix}-iot"
  target_key_id = aws_kms_key.iot.key_id
}

# CloudWatch Log Group for IoT Core
resource "aws_cloudwatch_log_group" "iot_core" {
  name              = "/aws/iot/${local.name_prefix}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.iot.arn

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-core-logs"
    }
  )
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.iot.arn

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-lambda-logs"
    }
  )
}

# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name_prefix}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.iot.arn

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-logs"
    }
  )
}

# IAM Role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_logs_role" {
  name = "${local.name_prefix}-cloudtrail-cloudwatch-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-cw-role"
    }
  )
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs_policy" {
  name = "${local.name_prefix}-cloudtrail-cloudwatch-logs-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# S3 Bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.name_prefix}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-logs"
    }
  )
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.iot.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
}

# CloudTrail for audit logging
resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_logs_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-trail"
    }
  )
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-guardduty"
    }
  )
}

# S3 Bucket for IoT historical data
resource "aws_s3_bucket" "iot_data" {
  bucket = "${local.name_prefix}-iot-data-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-data"
    }
  )
}

resource "aws_s3_bucket_versioning" "iot_data" {
  bucket = aws_s3_bucket.iot_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "iot_data" {
  bucket = aws_s3_bucket.iot_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.iot.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "iot_data" {
  bucket = aws_s3_bucket.iot_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy to move data to Glacier after 90 days
resource "aws_s3_bucket_lifecycle_configuration" "iot_data" {
  bucket = aws_s3_bucket.iot_data.id

  rule {
    id     = "archive-old-data"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years
    }
  }
}

# Enable S3 access logging
resource "aws_s3_bucket" "iot_data_logs" {
  bucket = "${local.name_prefix}-iot-data-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-data-logs"
    }
  )
}

resource "aws_s3_bucket_server_side_encryption_configuration" "iot_data_logs" {
  bucket = aws_s3_bucket.iot_data_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.iot.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "iot_data_logs" {
  bucket = aws_s3_bucket.iot_data_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "iot_data" {
  bucket = aws_s3_bucket.iot_data.id

  target_bucket = aws_s3_bucket.iot_data_logs.id
  target_prefix = "access-logs/"
}

# DynamoDB Table for device state
resource "aws_dynamodb_table" "device_state" {
  name           = "${local.name_prefix}-device-state"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "device_id"
  range_key      = "timestamp"
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "device_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  ttl {
    attribute_name = "expiration_time"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.iot.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-device-state"
    }
  )

  lifecycle {
    prevent_destroy = true
  }
}

# DynamoDB Table for device metadata
resource "aws_dynamodb_table" "device_metadata" {
  name         = "${local.name_prefix}-device-metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device_id"

  attribute {
    name = "device_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.iot.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-device-metadata"
    }
  )

  lifecycle {
    prevent_destroy = true
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "${local.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-lambda-role"
    }
  )
}

# IAM Policy for Lambda to write to DynamoDB and S3
resource "aws_iam_role_policy" "lambda_policy" {
  name = "${local.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.device_state.arn,
          aws_dynamodb_table.device_metadata.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.iot_data.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.iot.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      }
    ]
  })
}

# Lambda Function for processing IoT data
resource "aws_lambda_function" "iot_processor" {
  filename      = "lambda_placeholder.zip"
  function_name = "${local.name_prefix}-iot-processor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs.18.x"
  timeout       = 60
  memory_size   = 256

  environment {
    variables = {
      DEVICE_STATE_TABLE    = aws_dynamodb_table.device_state.name
      DEVICE_METADATA_TABLE = aws_dynamodb_table.device_metadata.name
      IOT_DATA_BUCKET       = aws_s3_bucket.iot_data.id
      LOG_GROUP             = aws_cloudwatch_log_group.lambda.name
    }
  }

  vpc_config {
    security_group_ids = []
    subnet_ids         = []
  }

  layers = []

  ephemeral_storage {
    size = 512
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-processor"
    }
  )

  depends_on = [
    aws_iam_role_policy.lambda_policy,
    aws_cloudwatch_log_group.lambda
  ]
}

# IAM Role for IoT Core
resource "aws_iam_role" "iot_core_role" {
  name = "${local.name_prefix}-iot-core-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "iot.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-core-role"
    }
  )
}

# IAM Policy for IoT Core to invoke Lambda
resource "aws_iam_role_policy" "iot_core_policy" {
  name = "${local.name_prefix}-iot-core-policy"
  role = aws_iam_role.iot_core_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.iot_processor.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.iot_core.arn}:*"
      }
    ]
  })
}

# IoT Core Logging
resource "aws_iot_logging_options" "main" {
  default_log_level = "INFO"
  enabled           = true
  role_arn          = aws_iam_role.iot_core_role.arn
  log_target_configuration {
    enabled       = true
    log_level     = "INFO"
    target_type   = "CLOUD_WATCH_LOGS"
    target        = aws_cloudwatch_log_group.iot_core.arn
  }
}

# IoT Thing Group
resource "aws_iot_thing_group" "main" {
  name = "${local.name_prefix}-device-group"

  thing_group_properties {
    description = "IoT device group for ${local.name_prefix}"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-device-group"
    }
  )
}

# IoT Topic Rule for routing messages to Lambda
resource "aws_iot_topic_rule" "device_telemetry" {
  name        = replace("${local.name_prefix}_device_telemetry", "-", "_")
  enabled     = true
  sql         = "SELECT * FROM 'dt/+/telemetry'"
  sql_version = "2016-03-23"

  lambda {
    function_arn = aws_lambda_function.iot_processor.arn
  }

  error_action {
    cloudwatch_logs {
      log_group_name = aws_cloudwatch_log_group.iot_core.name
      role_arn       = aws_iam_role.iot_core_role.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.iot_core_policy,
    aws_lambda_permission.allow_iot
  ]
}

# Lambda permission for IoT Core to invoke
resource "aws_lambda_permission" "allow_iot" {
  statement_id  = "AllowExecutionFromIoT"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iot_processor.function_name
  principal     = "iot.amazonaws.com"
  source_arn    = "arn:aws:iot:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${replace("${local.name_prefix}_device_telemetry", "-", "_")}"
}

# CloudWatch Alarms for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Alert when Lambda function has errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.iot_processor.function_name
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-lambda-errors-alarm"
    }
  )
}

# CloudWatch Alarm for DynamoDB throttling
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttle" {
  alarm_name          = "${local.name_prefix}-dynamodb-throttle"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsumedWriteCapacityUnits"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Sum"
  threshold           = 1000
  alarm_description   = "Alert when DynamoDB write capacity is high"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.device_state.name
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-dynamodb-throttle-alarm"
    }
  )
}

# CloudWatch Alarm for IoT Core rule failures
resource "aws_cloudwatch_metric_alarm" "iot_rule_failures" {
  alarm_name          = "${local.name_prefix}-iot-rule-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Failure"
  namespace           = "AWS/IoT"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Alert when IoT rule has failures"
  treat_missing_data  = "notBreaching"

  dimensions = {
    RuleName = aws_iot_topic_rule.device_telemetry.name
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-iot-rule-failures-alarm"
    }
  )
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}
```