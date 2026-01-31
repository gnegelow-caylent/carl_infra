# Redundant Web Application Infrastructure on AWS

## Overview

This Terraform configuration deploys a highly available, redundant web application infrastructure on AWS using an Application Load Balancer (ALB) with Auto Scaling Group across multiple Availability Zones. The architecture is designed for traditional applications with predictable workloads and includes multi-AZ RDS database failover, VPC Flow Logs for compliance monitoring, and a 3-tier subnet design (public, application, data) to meet SOC 2 availability and security requirements.

**Environment:** dev  
**Resource Prefix:** test  
**VPC CIDR:** 10.2.0.0/16  
**Estimated Monthly Cost:** $250-400

## SOC 2 Controls Addressed

This infrastructure implements controls across multiple SOC 2 Trust Service Criteria:

- **CC6.1** - Logical Access Controls: VPC security groups restrict traffic to authorized sources
- **CC6.7** - Encryption: Data in transit (TLS/SSL) and at rest (RDS encryption, EBS encryption)
- **CC7.1** - System Monitoring: VPC Flow Logs capture all network traffic for audit trails
- **CC7.2** - Incident Response: CloudWatch alarms and logs enable detection and response
- **A1.3** - Availability: Multi-AZ deployment with Auto Scaling ensures service continuity
- **PI1.1** - Processing Integrity: RDS Multi-AZ with automatic failover (<2 min) maintains data consistency
- **P1** - Privacy: Network segmentation and encryption protect sensitive data

## Security Best Practices Implemented

- **High Availability:** 2-4 t3.medium instances across 2 Availability Zones with automatic failover
- **Load Balancing:** Application Load Balancer distributes traffic and performs health checks
- **Database Redundancy:** RDS Multi-AZ with automatic failover and encrypted storage
- **Network Segmentation:** 3-tier subnet architecture (public, application, data) isolates workloads
- **Outbound Internet Access:** 2 NAT Gateways for redundant egress traffic
- **Compliance Logging:** VPC Flow Logs streamed to S3 for audit and forensic analysis
- **Encryption:** EBS volumes and RDS database encrypted at rest; TLS/SSL for data in transit
- **Security Groups:** Principle of least privilege with restrictive ingress/egress rules
- **Auto Scaling:** Automatic instance scaling based on demand (2-4 instances)

## Additional Recommendations

To further enhance security and compliance posture, consider implementing:

- **Amazon GuardDuty:** Enable threat detection for unauthorized access patterns and malware
- **Amazon Inspector:** Automated vulnerability scanning of EC2 instances and network reachability
- **AWS WAF:** Web Application Firewall on ALB to protect against common web exploits (SQL injection, XSS)
- **AWS Secrets Manager:** Centralized management of database credentials and API keys
- **CloudTrail:** API audit logging for all AWS API calls and resource changes
- **AWS Config:** Continuous compliance monitoring and configuration drift detection
- **SNS Notifications:** Alert on critical events (scaling actions, failovers, security group changes)
- **Systems Manager Session Manager:** Secure shell access to instances without SSH keys or bastion hosts
- **VPC Endpoints:** Private connectivity to AWS services without internet gateway exposure

## Prerequisites

Before deploying this infrastructure, ensure you have:

- **AWS Account:** Active AWS account with appropriate permissions (EC2, RDS, VPC, IAM, S3, CloudWatch)
- **Terraform:** Version 1.0 or later installed locally
- **AWS CLI:** Configured with credentials and default region
- **IAM Permissions:** User/role with permissions for:
  - EC2 (instances, security groups, key pairs, AMIs)
  - RDS (database creation, parameter groups, option groups)
  - VPC (subnets, route tables, NAT gateways, flow logs)
  - IAM (roles, policies, instance profiles)
  - S3 (bucket creation for VPC Flow Logs)
  - CloudWatch (log groups, alarms)
- **EC2 Key Pair:** Pre-created in your AWS region for SSH access to instances
- **S3 Bucket:** For storing VPC Flow Logs (can be created by Terraform)

## Usage Instructions

### 1. Initialize Terraform

```bash
terraform init
```

This downloads required providers and initializes the Terraform working directory.

### 2. Review the Execution Plan

```bash
terraform plan -out=tfplan
```

Review the resources that will be created. Verify the configuration matches your requirements.

### 3. Apply the Configuration

```bash
terraform apply tfplan
```

Terraform will create all resources. This typically takes 5-10 minutes.

### 4. Retrieve Outputs

```bash
terraform output
```

Capture the ALB DNS name, RDS endpoint, and other outputs for post-deployment configuration.

### 5. Destroy Resources (When No Longer Needed)

```bash
terraform destroy
```

Confirm the destruction of all resources to avoid unexpected charges.

## Resources Created

### Networking
- **VPC:** 10.2.0.0/16 with DNS hostnames enabled
- **Public Subnets:** 2 subnets (10.2.1.0/24, 10.2.2.0/24) in separate AZs for ALB and NAT Gateways
- **Application Subnets:** 2 subnets (10.2.11.0/24, 10.2.12.0/24) in separate AZs for EC2 instances
- **Data Subnets:** 2 subnets (10.2.21.0/24, 10.2.22.0/24) in separate AZs for RDS database
- **Internet Gateway:** Enables internet connectivity for public subnets
- **NAT Gateways:** 2 gateways (one per AZ) for redundant outbound internet access
- **Route Tables:** Separate routing for public, application, and data tiers

### Load Balancing & Auto Scaling
- **Application Load Balancer:** Distributes traffic across instances with health checks
- **Target Group:** Registers EC2 instances and performs HTTP health checks
- **Auto Scaling Group:** Maintains 2-4 t3.medium instances across 2 AZs
- **Launch Template:** Defines instance configuration (AMI, instance type, security groups, user data)

### Compute
- **EC2 Instances:** 2-4 t3.medium instances running application workload
- **Security Group (ALB):** Allows inbound HTTP/HTTPS from internet (0.0.0.0/0)
- **Security Group (App):** Allows inbound traffic from ALB only
- **Security Group (RDS):** Allows inbound traffic from app tier only

### Database
- **RDS Multi-AZ:** MySQL 8.0 database with automatic failover
- **DB Subnet Group:** Spans data tier subnets for Multi-AZ deployment
- **Parameter Group:** Database configuration (encryption, backups, etc.)
- **DB Security Group:** Restricts access to application tier only

### Monitoring & Compliance
- **VPC Flow Logs:** Captures all network traffic to S3 for audit trails
- **S3 Bucket:** Stores VPC Flow Logs with encryption and versioning
- **CloudWatch Log Group:** Aggregates application and system logs
- **IAM Role & Instance Profile:** Allows EC2 instances to write logs and access AWS services

## Inputs

| Variable | Type | Description | Default |
|----------|------|-------------|---------|
| `vpc_cidr` | string | CIDR block for VPC | `10.2.0.0/16` |
| `environment` | string | Environment name (dev, staging, prod) | `dev` |
| `resource_prefix` | string | Prefix for all resource names | `test` |
| `instance_type` | string | EC2 instance type | `t3.medium` |
| `min_size` | number | Minimum number of instances in ASG | `2` |
| `max_size` | number | Maximum number of instances in ASG | `4` |
| `desired_capacity` | number | Desired number of instances in ASG | `2` |
| `db_engine_version` | string | RDS MySQL version | `8.0.35` |
| `db_instance_class` | string | RDS instance type | `db.t3.micro` |
| `db_allocated_storage` | number | RDS storage in GB | `20` |
| `db_username` | string | RDS master username | `admin` |
| `db_password` | string | RDS master password (sensitive) | `` |
| `enable_flow_logs` | bool | Enable VPC Flow Logs | `true` |
| `enable_monitoring` | bool | Enable detailed CloudWatch monitoring | `true` |
| `tags` | map(string) | Tags applied to all resources | `{}` |

## Outputs

| Output | Description |
|--------|-------------|
| `vpc_id` | VPC ID |
| `alb_dns_name` | DNS name of the Application Load Balancer |
| `alb_arn` | ARN of the Application Load Balancer |
| `asg_name` | Name of the Auto Scaling Group |
| `rds_endpoint` | RDS database endpoint (host:port) |
| `rds_database_name` | RDS database name |
| `public_subnet_ids` | List of public subnet IDs |
| `app_subnet_ids` | List of application subnet IDs |
| `data_subnet_ids` | List of data subnet IDs |
| `s3_flow_logs_bucket` | S3 bucket name for VPC Flow Logs |
| `cloudwatch_log_group` | CloudWatch log group name |

## Post-Deployment Steps

### 1. Verify Infrastructure Health

```bash
# Check ALB target health
aws elbv2 describe-target-health --target-group-arn <target-group-arn>

# Verify Auto Scaling Group
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names test-dev-asg

# Test ALB connectivity
curl http://<alb-dns-name>
```

### 2. Configure Database

```bash
# Connect to RDS database
mysql -h <rds-endpoint> -u admin -p

# Create application database and user
CREATE DATABASE app_db;
CREATE USER 'app_user'@'%' IDENTIFIED BY '<strong-password>';
GRANT ALL PRIVILEGES ON app_db.* TO 'app_user'@'%';
FLUSH PRIVILEGES;
```

### 3. Deploy Application

- Upload application code to EC2 instances via Systems Manager Session Manager or custom AMI
- Configure application to connect to RDS endpoint
- Verify application health checks pass in ALB target group

### 4. Configure CloudWatch Alarms

```bash
# Create alarm for high CPU utilization
aws cloudwatch put-metric-alarm \
  --alarm-name test-dev-high-cpu \
  --alarm-description "Alert when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2
```

### 5. Review VPC Flow Logs

```bash
# Query VPC Flow Logs in S3
aws s3 ls s3://<flow-logs-bucket>/
```

### 6. Test Failover Scenarios

- Terminate an EC2 instance and verify Auto Scaling replaces it
- Simulate RDS failover and verify application reconnects
- Test NAT Gateway failover by monitoring outbound traffic

### 7. Enable Additional Security Services

- Enable GuardDuty for threat detection
- Enable Inspector for vulnerability scanning
- Deploy WAF rules on ALB for web application protection

### 8. Document Configuration

- Record RDS master password in AWS Secrets Manager
- Document application deployment procedures
- Create runbooks for common operational tasks (scaling, patching, failover)

### 9. Schedule Maintenance

- Plan monthly security patching for EC2 instances
- Schedule RDS maintenance windows during low-traffic periods
- Review and rotate database credentials quarterly

### 10. Monitor Compliance

- Review VPC Flow Logs weekly for unauthorized access attempts
- Run AWS Config