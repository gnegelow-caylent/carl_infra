# Event-Driven Serverless IoT Application Architecture

## Overview

This Terraform configuration deploys a serverless IoT application architecture on AWS designed for small to medium IoT deployments (up to 10,000 devices). The architecture uses AWS IoT Core to receive device messages via MQTT/HTTPS, routes them through the IoT Rules Engine to Lambda functions for processing, stores device state in DynamoDB, and archives historical data in S3. This event-driven approach provides a cost-effective, scalable foundation for IoT telemetry collection and processing without requiring always-on compute resources.

**Deployment Environment:** `dev`  
**Resource Prefix:** `test`  
**VPC CIDR:** `10.1.0.0/16`  
**Estimated Monthly Cost:** $50-300 (depending on device count and message volume)

---

## SOC 2 Controls Addressed

This architecture implements controls across multiple SOC 2 Trust Service Criteria:

| Control | Description | Implementation |
|---------|-------------|-----------------|
| **CC6.1** | Logical Access Controls | AWS IoT Core device certificate authentication; IAM policies restrict Lambda, DynamoDB, and S3 access by role |
| **CC6.6** | Encryption of Data in Transit | MQTT over TLS 1.2+; HTTPS for device communication; encrypted SNS/SQS topics |
| **CC6.7** | Encryption of Data at Rest | DynamoDB encryption enabled; S3 default encryption (AES-256); CloudWatch Logs encrypted |
| **CC7.1** | System Monitoring | CloudWatch Logs capture Lambda execution and errors; IoT Core metrics monitored |
| **CC7.2** | Incident Response | CloudTrail logs all API calls; CloudWatch alarms trigger on Lambda errors and DynamoDB throttling |
| **A1.3** | Availability Monitoring | CloudWatch alarms on Lambda duration and error rates; DynamoDB on-demand scaling prevents throttling |
| **PI1.1** | Processing Integrity | Lambda validates device data before writing to DynamoDB; audit trail via CloudTrail |

---

## Security Best Practices Implemented

### Encryption & Data Protection
- **In Transit:** MQTT over TLS 1.2+; HTTPS endpoints for device communication
- **At Rest:** DynamoDB encryption with AWS-managed keys; S3 default encryption; CloudWatch Logs encrypted
- **Key Management:** AWS-managed keys (no customer-managed CMK required for this tier)

### Access Control
- **Device Authentication:** AWS IoT Core X.509 certificate-based authentication
- **Service Authorization:** IAM roles with least-privilege policies for Lambda, DynamoDB, and S3
- **API Access:** CloudTrail logs all AWS API calls for audit trail

### Monitoring & Logging
- **CloudWatch Logs:** Lambda execution logs, errors, and warnings captured
- **CloudWatch Metrics:** IoT Core message count, Lambda duration, DynamoDB consumed capacity
- **CloudWatch Alarms:** Alerts on Lambda errors, DynamoDB throttling, and high message latency
- **CloudTrail:** API audit logging enabled for compliance and forensics

### Data Lifecycle
- **S3 Lifecycle Policies:** Historical data transitioned to Glacier after 90 days for cost optimization
- **DynamoDB TTL:** Optional time-to-live for automatic cleanup of stale device state

### Network Isolation (Optional)
- VPC not required initially; Lambda runs in AWS-managed VPC
- VPC support available if connecting to on-premises systems or private databases

---

## Additional Recommendations

### Immediate (High Priority)
- **AWS GuardDuty:** Enable threat detection for IoT Core and Lambda; detects unusual API patterns and compromised credentials
- **AWS Config:** Monitor compliance of IoT Core policies and Lambda configurations against security baselines
- **CloudWatch Alarms:** Configure SNS notifications for Lambda errors, DynamoDB throttling, and unauthorized API calls

### Short-term (Medium Priority)
- **AWS Secrets Manager:** Store device certificates and API keys securely; rotate credentials every 90 days
- **VPC Endpoints:** If using private DynamoDB/S3, deploy VPC endpoints to prevent data exfiltration
- **Lambda Layers:** Centralize security scanning and logging libraries across Lambda functions
- **IoT Device Defender:** Monitor device behavior anomalies (unusual message patterns, certificate misuse)

### Long-term (Lower Priority)
- **AWS IoT Analytics:** Add time-series analytics for device telemetry trends and anomaly detection
- **AWS IoT Events:** Implement complex event processing for multi-device correlations
- **Amazon Kinesis:** Upgrade to streaming layer if message volume exceeds 100K messages/day
- **AWS Certificate Manager:** Automate device certificate renewal and revocation

---

## Prerequisites

### AWS Account & Permissions
- AWS account with permissions to create IoT Core, Lambda, DynamoDB, S3, CloudWatch, and IAM resources
- Existing VPC (or use default VPC; this architecture can run in default VPC)
- AWS CLI v2 installed and configured with appropriate credentials

### Local Tools
- **Terraform:** v1.0 or later
- **Git:** For version control (optional)

### Networking
- No Transit Gateway required (not deployed in this configuration)
- Internet connectivity for devices to reach AWS IoT Core endpoints
- Optional: VPN or Direct Connect for on-premises device connectivity

### Compliance Requirements
- CloudTrail enabled in AWS account (for audit logging)
- CloudWatch Logs retention policy set to at least 90 days
- S3 bucket versioning enabled (optional but recommended)

---

## Usage Instructions

### 1. Initialize Terraform

```bash
terraform init
```

This downloads the AWS provider and initializes the Terraform working directory.

### 2. Review the Deployment Plan

```bash
terraform plan -out=tfplan
```

Review the resources that will be created. Look for:
- IoT Core Thing, Certificate, and Policy
- Lambda function with execution role
- DynamoDB table with encryption enabled
- S3 bucket with lifecycle policies
- CloudWatch Log Groups and Alarms

### 3. Apply the Configuration

```bash
terraform apply tfplan
```

Terraform will create all resources. This typically takes 2-3 minutes.

### 4. Verify Deployment

```bash
terraform output
```

Capture the outputs (IoT endpoint, DynamoDB table name, S3 bucket name) for post-deployment configuration.

### 5. Destroy Resources (When Done)

```bash
terraform destroy
```

This removes all resources created by this configuration.

---

## Resources Created

| Resource Type | Resource Name | Purpose |
|---------------|---------------|---------|
| **AWS IoT Core** | `test-iot-thing` | Device registration and MQTT endpoint |
| **AWS IoT Certificate** | `test-device-cert` | X.509 certificate for device authentication |
| **AWS IoT Policy** | `test-iot-policy` | Authorization policy for device MQTT operations |
| **AWS IoT Rule** | `test-iot-rule` | Routes messages to Lambda for processing |
| **Lambda Function** | `test-iot-processor` | Processes telemetry data and writes to DynamoDB |
| **Lambda Execution Role** | `test-lambda-role` | IAM role with permissions for DynamoDB and S3 access |
| **DynamoDB Table** | `test-device-state` | Stores current device state and metadata |
| **S3 Bucket** | `test-iot-archive-{account-id}` | Archives historical telemetry data |
| **S3 Lifecycle Policy** | (embedded) | Transitions data to Glacier after 90 days |
| **CloudWatch Log Group** | `/aws/lambda/test-iot-processor` | Lambda execution logs |
| **CloudWatch Log Group** | `/aws/iot/test-iot-rule` | IoT Rule Engine logs |
| **CloudWatch Alarms** | `test-lambda-errors`, `test-dynamodb-throttle` | Alerts on errors and throttling |
| **CloudTrail** | (account-level) | API audit logging (must be enabled separately) |

---

## Inputs

| Variable Name | Type | Description | Default | Required |
|---------------|------|-------------|---------|----------|
| `environment` | string | Deployment environment (dev, staging, prod) | `dev` | Yes |
| `resource_prefix` | string | Prefix for all resource names | `test` | Yes |
| `vpc_cidr` | string | CIDR block for VPC | `10.1.0.0/16` | No |
| `aws_region` | string | AWS region for deployment | `us-east-1` | No |
| `iot_message_retention_days` | number | CloudWatch Logs retention for IoT rules | `7` | No |
| `lambda_timeout_seconds` | number | Lambda function timeout | `30` | No |
| `lambda_memory_mb` | number | Lambda function memory allocation | `256` | No |
| `dynamodb_billing_mode` | string | DynamoDB billing mode (PAY_PER_REQUEST or PROVISIONED) | `PAY_PER_REQUEST` | No |
| `s3_lifecycle_transition_days` | number | Days before S3 data transitions to Glacier | `90` | No |
| `enable_cloudtrail` | bool | Enable CloudTrail for API audit logging | `true` | No |
| `enable_guardduty` | bool | Enable GuardDuty for threat detection | `false` | No |
| `cloudwatch_alarm_email` | string | Email for CloudWatch alarm notifications | `` | No |

---

## Outputs

| Output Name | Description |
|-------------|-------------|
| `iot_endpoint` | AWS IoT Core endpoint URL for device connections |
| `iot_thing_name` | Name of the registered IoT Thing |
| `device_certificate_arn` | ARN of the device X.509 certificate |
| `device_certificate_id` | Certificate ID for device provisioning |
| `dynamodb_table_name` | Name of the DynamoDB table storing device state |
| `dynamodb_table_arn` | ARN of the DynamoDB table |
| `s3_bucket_name` | Name of the S3 bucket for historical data archive |
| `s3_bucket_arn` | ARN of the S3 bucket |
| `lambda_function_name` | Name of the Lambda processor function |
| `lambda_function_arn` | ARN of the Lambda processor function |
| `lambda_role_arn` | ARN of the Lambda execution role |
| `cloudwatch_log_group_lambda` | CloudWatch Log Group for Lambda execution |
| `cloudwatch_log_group_iot` | CloudWatch Log Group for IoT Rule Engine |
| `cloudwatch_alarm_lambda_errors` | CloudWatch Alarm for Lambda errors |
| `cloudwatch_alarm_dynamodb_throttle` | CloudWatch Alarm for DynamoDB throttling |

---

## Post-Deployment Steps

### 1. Download Device Certificate

```bash
# Retrieve the device certificate from AWS Secrets Manager or IoT Core
aws iot describe-certificate --certificate-id $(terraform output -raw device_certificate_id)
```

Store the certificate securely on your IoT device. This is required for MQTT authentication.

### 2. Configure CloudWatch Alarms

```bash
# Subscribe to SNS topic for alarm notifications (if email provided)
aws sns subscribe \
  --topic-arn $(terraform output -raw cloudwatch_alarm_topic_arn) \
  --protocol email \
  --notification-endpoint your-email@example.com
```

Confirm the SNS subscription via email.

### 3. Test Device Connectivity

```bash
# Use AWS IoT Device SDK or MQTT client to publish a test message
mosquitto_pub -h $(terraform output -raw iot_endpoint) \
  -p 8883 \
  --cert device-cert.pem \
  --key device-key.pem \
  --cafile AmazonRootCA1.pem \
  -t "test/telemetry" \
  -m '{"temperature": 22.5, "humidity": 45}'
```

Verify the message appears in CloudWatch Logs for the Lambda function.

### 4. Verify DynamoDB Data

```bash
# Query the device state table
aws dynamodb scan \
  --table-name $(terraform output -raw dynamodb_table_name) \
  --limit 10
```

Confirm device state is being written correctly.

### 5. Review