# Multi-AZ RDS Infrastructure with Transit Gateway - README

## Overview

This Terraform configuration deploys a production-grade, multi-availability zone (Multi-AZ) RDS instance within a VPC designed for SOC 2 Type II compliance. The infrastructure includes encrypted databases, isolated subnets across multiple AZs, comprehensive logging, and network isolation controls. While Transit Gateway integration is not currently enabled, the architecture supports future TGW connectivity for hybrid or multi-VPC scenarios.

**Key Components:**
- Multi-AZ RDS instance (PostgreSQL/MySQL) with automated backups and encryption
- VPC with public and private subnets across 2+ availability zones
- RDS subnet group for Multi-AZ failover
- Security groups with least-privilege access controls
- Encrypted storage at rest and in transit
- Enhanced monitoring and audit logging
- VPC Flow Logs for network traffic analysis

---

## SOC 2 Controls Addressed

| Control | Description | Implementation |
|---------|-------------|-----------------|
| **CC6.1** | Logical Access - Unique IDs & Authentication | RDS IAM database authentication, security group rules with specific CIDR blocks |
| **CC6.6** | System Boundaries - Network Access Restriction | Private subnets, security groups, NACLs, RDS not publicly accessible |
| **CC6.7** | Encryption - Data at Rest & in Transit | RDS encryption enabled (KMS), SSL/TLS for connections, encrypted EBS volumes |
| **CC7.1** | Threat Detection - Security Monitoring | RDS Enhanced Monitoring, CloudWatch alarms for anomalies |
| **CC7.2** | Logging & Monitoring - Activity Audit Trail | RDS audit logs, VPC Flow Logs, CloudTrail for API calls, 7-year retention |
| **CC8.1** | Change Management - Infrastructure Control | Terraform state management, version control, documented change procedures |
| **A1.3** | Availability - System Uptime & Failover | Multi-AZ deployment, automated failover, backup retention |
| **PI1.1** | Processing Integrity - Accurate Data Processing | Transaction logging, audit trails, data validation |

---

## Security Best Practices Implemented

✅ **Encryption**
- RDS encryption at rest using AWS KMS (customer-managed or AWS-managed keys)
- SSL/TLS encryption in transit (enforced via security group rules)
- Encrypted automated backups and snapshots

✅ **Access Control**
- RDS instances deployed in private subnets (no public IP)
- Security groups restrict inbound traffic to specific application subnets
- IAM database authentication option for credential-less access
- Least-privilege security group rules

✅ **Logging & Monitoring**
- RDS Enhanced Monitoring (OS-level metrics every 1-60 seconds)
- RDS audit logs (login, query, error events)
- VPC Flow Logs for network traffic analysis
- CloudWatch alarms for CPU, storage, connections, and failover events
- CloudTrail logging for all API calls (7-year retention)

✅ **High Availability**
- Multi-AZ deployment with synchronous replication
- Automated failover to standby instance (typically <2 minutes)
- Automated backups with configurable retention (7-35 days)
- Manual snapshot capability for long-term retention

✅ **Network Isolation**
- VPC with CIDR 10.0.0.0/16
- Private subnets for RDS (no direct internet access)
- Network ACLs for additional layer of access control
- VPC endpoints for AWS service access (optional)

---

## Additional Recommendations for Enhanced Compliance

### Immediate (High Priority)
- **AWS Secrets Manager**: Store RDS master password and rotate every 30 days (CC6.1)
- **CloudWatch Alarms**: Configure alerts for failed login attempts, storage threshold, CPU >80% (CC7.1)
- **RDS Backup Vault**: Use AWS Backup for centralized, encrypted backup management with compliance policies (A1.3)
- **Parameter Groups**: Enable slow query logging and audit logging in RDS parameter group (CC7.2)

### Short-term (Medium Priority)
- **Amazon GuardDuty**: Enable for threat detection on VPC Flow Logs and CloudTrail (CC7.1)
- **AWS Config**: Monitor RDS encryption, backup retention, and Multi-AZ status compliance (CC8.1)
- **VPC Endpoints**: Add S3 and Secrets Manager endpoints to reduce internet exposure (CC6.6)
- **Database Activity Monitoring (DAM)**: Consider third-party tools (e.g., Imperva, Varonis) for advanced SQL monitoring (CC7.2)

### Medium-term (Lower Priority)
- **Transit Gateway Integration**: Enable for multi-VPC or hybrid connectivity with centralized logging (CC6.6)
- **AWS Systems Manager Session Manager**: Replace SSH/bastion hosts for RDS access (CC6.1)
- **RDS Proxy**: Add connection pooling and credential management layer (CC6.1, PI1.1)
- **Automated Remediation**: Use AWS Lambda + SNS to auto-remediate non-compliant configurations (CC8.1)

---

## Prerequisites

### AWS Account & Permissions
- AWS account with permissions to create VPC, RDS, IAM, CloudWatch, CloudTrail resources
- IAM user/role with `ec2:*`, `rds:*`, `kms:*`, `logs:*`, `cloudwatch:*` permissions
- KMS key access for RDS encryption (or create new key)

### Local Environment
- **Terraform**: v1.0 or later
- **AWS CLI**: v2.x (for credential configuration)
- **Git**: For version control of Terraform code

### AWS Service Limits
- Verify RDS instance quota in target region (default: 40 instances)
- Verify VPC quota (default: 5 per region)
- Verify Elastic IP quota if using NAT Gateway (default: 5 per region)

### Networking
- Determine application subnet CIDR for RDS security group ingress rules
- Plan for future Transit Gateway attachment (reserve subnet space if needed)
- Document DNS naming convention for RDS endpoint

---

## Usage Instructions

### 1. Initialize Terraform

```bash
# Clone or create Terraform configuration directory
mkdir -p terraform-rds && cd terraform-rds

# Initialize Terraform (downloads providers and modules)
terraform init

# Verify AWS credentials are configured
aws sts get-caller-identity
```

### 2. Review Configuration

```bash
# Create terraform.tfvars with your values
cat > terraform.tfvars <<EOF
vpc_cidr           = "10.0.0.0/16"
resource_prefix    = "carl"
environment        = "prod"
rds_engine          = "postgres"  # or "mysql"
rds_instance_class  = "db.t3.medium"
rds_allocated_storage = 100
rds_backup_retention = 30
EOF

# Validate configuration
terraform validate

# Preview changes (ALWAYS review before applying)
terraform plan -out=tfplan
```

### 3. Deploy Infrastructure

```bash
# Apply configuration (creates all resources)
terraform apply tfplan

# Capture outputs for reference
terraform output -json > outputs.json
```

### 4. Verify Deployment

```bash
# Confirm RDS instance is available
aws rds describe-db-instances \
  --db-instance-identifier carl-prod-rds \
  --query 'DBInstances[0].[DBInstanceStatus,MultiAZ,StorageEncrypted]'

# Check security group rules
aws ec2 describe-security-groups \
  --filters "Name=tag:Name,Values=carl-prod-rds-sg" \
  --query 'SecurityGroups[0].IpPermissions'

# Verify VPC Flow Logs are enabled
aws ec2 describe-flow-logs \
  --filter "Name=resource-id,Values=<vpc-id>"
```

---

## Resources Created

| Resource Type | Resource Name | Purpose |
|---------------|---------------|---------|
| **VPC** | `carl-prod-vpc` | Virtual Private Cloud (10.0.0.0/16) |
| **Subnets** | `carl-prod-private-subnet-az1`, `carl-prod-private-subnet-az2` | Private subnets for RDS (Multi-AZ) |
| **Subnets** | `carl-prod-public-subnet-az1`, `carl-prod-public-subnet-az2` | Public subnets for NAT Gateway (optional) |
| **Internet Gateway** | `carl-prod-igw` | Internet connectivity for VPC |
| **NAT Gateway** | `carl-prod-nat-gw` | Outbound internet access for private subnets |
| **Route Tables** | `carl-prod-public-rt`, `carl-prod-private-rt` | Route traffic within VPC and to internet |
| **Security Group** | `carl-prod-rds-sg` | Inbound rules for RDS (port 5432/3306) |
| **RDS Subnet Group** | `carl-prod-rds-subnet-group` | Multi-AZ subnet configuration for RDS |
| **RDS Instance** | `carl-prod-rds` | Multi-AZ PostgreSQL/MySQL database |
| **RDS Parameter Group** | `carl-prod-rds-params` | Database configuration (logging, encryption) |
| **KMS Key** | `carl-prod-rds-key` | Customer-managed key for RDS encryption |
| **CloudWatch Log Group** | `/aws/rds/instance/carl-prod-rds/error` | RDS error logs |
| **CloudWatch Log Group** | `/aws/rds/instance/carl-prod-rds/audit` | RDS audit logs |
| **VPC Flow Logs** | `carl-prod-vpc-flow-logs` | Network traffic analysis |
| **CloudWatch Alarms** | `carl-prod-rds-cpu`, `carl-prod-rds-storage`, etc. | Monitoring and alerting |
| **IAM Role** | `carl-prod-rds-monitoring-role` | Enhanced Monitoring permissions |

---

## Inputs (Variables)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `vpc_cidr` | string | `"10.0.0.0/16"` | CIDR block for VPC |
| `resource_prefix` | string | `"carl"` | Prefix for all resource names |
| `environment` | string | `"prod"` | Environment tag (prod, staging, dev) |
| `rds_engine` | string | `"postgres"` | Database engine (postgres, mysql, mariadb) |
| `rds_engine_version` | string | `"14.7"` | RDS engine version |
| `rds_instance_class` | string | `"db.t3.medium"` | RDS instance type |
| `rds_allocated_storage` | number | `100` | Storage allocation in GB |
| `rds_max_allocated_storage` | number | `200` | Maximum storage for autoscaling |
| `rds_backup_retention` | number | `30` | Backup retention in days (7-35) |
| `rds_backup_window` | string | `"03:00-04:00"` | Preferred backup window (UTC) |
| `rds_maintenance_window` | string | `"sun:04:00-sun:05:00"` | Preferred maintenance window |
| `rds_multi_az` | bool | `true` | Enable Multi-AZ deployment |
| `rds_storage_encrypted` | bool | `true` | Enable encryption at rest |
| `rds_enable_iam_auth` | bool | `true` | Enable IAM database authentication |
| `rds_enable_audit_log` | bool | `true` | Enable audit logging |
| `rds_enable_error_log` | bool | `true` | Enable error logging |
| `rds_enable_enhanced_monitoring` | bool | `true` | Enable Enhanced Monitoring |
| `rds_monitoring_interval` | number | `60` | Enhanced Monitoring interval (seconds) |
| `app_subnet_cidr` | string | `"10.1.0.0/24"` | Application subnet CIDR for security group |
| `enable_flow_logs` | bool