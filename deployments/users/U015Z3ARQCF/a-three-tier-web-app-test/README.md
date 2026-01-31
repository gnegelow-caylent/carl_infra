# Three-Tier Web Application on AWS ECS Fargate with RDS Multi-AZ

## Overview

This Terraform configuration deploys a production-ready, SOC 2 compliant three-tier web application architecture on AWS using ECS Fargate and RDS Multi-AZ. The infrastructure spans two Availability Zones for high availability and includes comprehensive security controls, automated backups, and network isolation.

**Architecture Components:**
- **Presentation Tier**: Application Load Balancer in public subnets
- **Application Tier**: ECS Fargate containers (auto-scaling 2-10 tasks) in private app subnets
- **Data Tier**: RDS Multi-AZ PostgreSQL/MySQL in isolated data subnets
- **Networking**: VPC with three-tier subnet design, NAT Gateways, Gateway Endpoints, and VPC Flow Logs

**Estimated Monthly Cost**: $350-700 (depending on scale and data transfer)

---

## SOC 2 Controls Addressed

This infrastructure implements the following SOC 2 Trust Service Criteria:

| Control | Implementation |
|---------|-----------------|
| **CC6.1** - Logical Access Control | IAM task roles with least privilege permissions; no root credentials used |
| **CC6.6** - Network Segmentation | Private app and data subnets; security groups restrict traffic by port/protocol |
| **CC6.7** - Encryption | KMS encryption at rest for RDS and EFS; TLS for data in transit |
| **CC7.1** - System Monitoring | VPC Flow Logs captured to S3; CloudWatch metrics for ECS and RDS |
| **CC7.2** - Incident Response | VPC Flow Logs enable network forensics; CloudWatch alarms for anomalies |
| **A1.1** - Availability | Multi-AZ RDS with automatic failover; ECS auto-scaling across AZs |
| **A1.2** - Disaster Recovery | Automated RDS backups with 30-day retention; cross-AZ replication |
| **A1.3** - Capacity Planning | ECS auto-scaling policies (2-10 tasks); RDS monitoring for performance |
| **PI1.1** - Processing Integrity | Database transaction logs; automated backups ensure data consistency |

---

## Security Best Practices Implemented

✅ **Encryption**
- RDS encrypted at rest with AWS KMS
- EBS volumes encrypted by default
- S3 buckets for Flow Logs use server-side encryption

✅ **Network Security**
- VPC with public/private/data subnet isolation
- Security groups enforce least privilege (ALB → ECS → RDS)
- NAT Gateways provide outbound internet access for private subnets
- No direct internet access to application or data tiers

✅ **Logging & Monitoring**
- VPC Flow Logs to S3 for network traffic analysis
- CloudWatch Logs for ECS container output
- RDS Performance Insights and Enhanced Monitoring
- ALB access logs (optional, configurable)

✅ **Access Control**
- IAM task roles with specific permissions per container
- RDS uses security groups (no public endpoint)
- Secrets Manager integration ready for database credentials

✅ **High Availability**
- Multi-AZ RDS with automatic failover
- ECS tasks distributed across AZs
- ALB health checks with automatic task replacement
- NAT Gateway in each AZ for redundancy

✅ **Backup & Recovery**
- Automated RDS backups with 30-day retention
- Point-in-time recovery enabled
- Backup encryption with KMS

---

## Additional Recommendations

The following enhancements should be considered for production deployments:

| Feature | Benefit | Effort |
|---------|---------|--------|
| **Amazon GuardDuty** | Threat detection for EC2, RDS, and S3 | Low |
| **Amazon Inspector** | Container image vulnerability scanning | Low |
| **AWS WAF** | DDoS and application layer protection on ALB | Medium |
| **AWS Secrets Manager** | Automated database credential rotation | Low |
| **AWS Config** | Compliance monitoring and drift detection | Medium |
| **CloudTrail** | API audit logging for compliance | Low |
| **SNS Notifications** | Alert on CloudWatch alarms and security events | Low |
| **RDS Proxy** | Connection pooling and credential management | Medium |
| **ECS Exec** | Secure shell access to running containers | Low |

---

## Prerequisites

Before deploying this infrastructure, ensure you have:

- **AWS Account** with appropriate permissions (EC2, ECS, RDS, VPC, IAM, KMS, S3, CloudWatch)
- **Terraform** >= 1.0 installed locally
- **AWS CLI** configured with credentials (`aws configure`)
- **Docker** (optional, for building custom container images)
- **VPC CIDR Block** 10.21.0.0/16 available in your AWS region
- **IAM Permissions** for:
  - VPC, subnets, security groups, NAT Gateways
  - ECS, ECR, CloudWatch
  - RDS, KMS, Secrets Manager
  - S3 (for Flow Logs and Terraform state)
  - IAM roles and policies

**Recommended AWS Region**: us-east-1, us-west-2, eu-west-1 (verify RDS instance availability)

---

## Usage Instructions

### 1. Initialize Terraform

```bash
terraform init
```

This downloads the AWS provider and initializes the working directory.

### 2. Review the Deployment Plan

```bash
terraform plan -out=tfplan
```

Review the resources that will be created. Verify:
- VPC CIDR: 10.21.0.0/16
- Resource prefix: test
- Environment: dev
- Availability Zones: 2

### 3. Apply the Configuration

```bash
terraform apply tfplan
```

Terraform will create all resources. This typically takes 5-10 minutes.

### 4. Verify Deployment

```bash
# Get ALB DNS name
terraform output alb_dns_name

# Check ECS cluster status
aws ecs describe-clusters --clusters test-dev-cluster --region us-east-1

# Verify RDS instance
aws rds describe-db-instances --db-instance-identifier test-dev-postgres --region us-east-1
```

### 5. Destroy Infrastructure (When Done)

```bash
terraform destroy
```

---

## Resources Created

### Networking
- **VPC**: 10.21.0.0/16 with DNS hostnames enabled
- **Public Subnets**: 2 subnets (10.21.0.0/24, 10.21.1.0/24) for ALB
- **App Subnets**: 2 subnets (10.21.10.0/24, 10.21.11.0/24) for ECS Fargate
- **Data Subnets**: 2 subnets (10.21.20.0/24, 10.21.21.0/24) for RDS
- **Internet Gateway**: For public subnet internet access
- **NAT Gateways**: 1 per AZ for private subnet outbound access
- **Route Tables**: Public, app, and data tier routing
- **VPC Flow Logs**: S3 bucket for network traffic logs

### Load Balancing
- **Application Load Balancer**: In public subnets, listening on HTTP/HTTPS
- **Target Group**: ECS Fargate tasks with health checks
- **Security Group**: ALB allows inbound 80/443, outbound to ECS

### Container Orchestration
- **ECS Cluster**: test-dev-cluster
- **ECS Task Definition**: Fargate-compatible (0.5-1 vCPU, 1-2GB RAM)
- **ECS Service**: Auto-scaling 2-10 tasks across AZs
- **CloudWatch Logs**: Container output and metrics
- **IAM Task Role**: Least privilege permissions for containers

### Database
- **RDS Instance**: Multi-AZ PostgreSQL/MySQL (db.t3.small)
- **DB Subnet Group**: Isolated data subnets
- **Security Group**: RDS allows inbound 5432/3306 from ECS only
- **Automated Backups**: 30-day retention with encryption
- **Enhanced Monitoring**: CloudWatch metrics for performance

### Security & Compliance
- **KMS Key**: Encryption for RDS, EBS, and S3
- **IAM Roles**: Task execution role and task role
- **Security Groups**: 3 groups (ALB, ECS, RDS) with least privilege rules
- **S3 Bucket**: VPC Flow Logs storage with encryption and versioning

### Monitoring
- **CloudWatch Log Groups**: ECS, RDS, VPC Flow Logs
- **CloudWatch Alarms**: CPU, memory, database connections (optional)
- **VPC Flow Logs**: Network traffic analysis

---

## Inputs

| Variable | Type | Description | Default |
|----------|------|-------------|---------|
| `aws_region` | string | AWS region for deployment | `us-east-1` |
| `vpc_cidr` | string | VPC CIDR block | `10.21.0.0/16` |
| `resource_prefix` | string | Prefix for all resource names | `test` |
| `environment` | string | Environment name (dev/staging/prod) | `dev` |
| `container_image` | string | Docker image URI for ECS tasks | `nginx:latest` |
| `container_port` | number | Port exposed by container | `80` |
| `container_cpu` | number | ECS task CPU units (256-4096) | `512` |
| `container_memory` | number | ECS task memory in MB (512-30720) | `1024` |
| `ecs_desired_count` | number | Desired number of ECS tasks | `2` |
| `ecs_min_capacity` | number | Minimum ECS tasks for auto-scaling | `2` |
| `ecs_max_capacity` | number | Maximum ECS tasks for auto-scaling | `10` |
| `rds_engine` | string | RDS database engine (postgres/mysql) | `postgres` |
| `rds_engine_version` | string | RDS engine version | `14.7` |
| `rds_instance_class` | string | RDS instance type | `db.t3.small` |
| `rds_allocated_storage` | number | RDS storage in GB | `20` |
| `rds_backup_retention_days` | number | Backup retention period | `30` |
| `rds_username` | string | RDS master username | `admin` |
| `enable_flow_logs` | bool | Enable VPC Flow Logs | `true` |
| `enable_enhanced_monitoring` | bool | Enable RDS Enhanced Monitoring | `true` |
| `tags` | map(string) | Additional tags for all resources | `{}` |

---

## Outputs

| Output | Description |
|--------|-------------|
| `vpc_id` | VPC ID |
| `alb_dns_name` | Application Load Balancer DNS name (use this to access your app) |
| `alb_arn` | ALB ARN |
| `ecs_cluster_name` | ECS cluster name |
| `ecs_service_name` | ECS service name |
| `rds_endpoint` | RDS database endpoint (hostname:port) |
| `rds_instance_id` | RDS instance identifier |
| `rds_security_group_id` | RDS security group ID |
| `ecs_task_role_arn` | IAM task role ARN for containers |
| `flow_logs_bucket_name` | S3 bucket name for VPC Flow Logs |
| `kms_key_id` | KMS key ID for encryption |

---

## Post-Deployment Steps

### 1. Verify Connectivity

```bash
# Get ALB DNS name
ALB_DNS=$(terraform output -raw alb_dns_name)

# Test HTTP access
curl http://$ALB_DNS

# Check ECS task logs
aws logs tail /ecs/test-dev-app --follow
```

### 2. Configure RDS Database

```bash
# Get RDS endpoint
RDS_ENDPOINT=$(terraform output -raw rds_endpoint)

# Connect to database (requires ps