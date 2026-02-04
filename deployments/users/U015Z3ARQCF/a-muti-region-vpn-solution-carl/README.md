# Multi-Region VPN Solution

## Overview

This Terraform configuration deploys a secure, multi-region VPN infrastructure on AWS designed for SOC 2 compliance. It establishes VPN connectivity between multiple AWS regions using customer-managed VPN connections, enabling encrypted communication across geographically distributed environments while maintaining strict access controls and comprehensive audit logging.

**Key Components:**
- VPN Customer Gateways and Virtual Private Gateways
- VPN Connections with IPSec encryption
- VPC peering or site-to-site connectivity
- CloudWatch monitoring and alarms
- VPC Flow Logs for network traffic analysis
- AWS CloudTrail for API audit logging

---

## SOC 2 Controls Addressed

| Control | Description | Implementation |
|---------|-------------|-----------------|
| **CC6.1** | Logical Access Controls | VPN authentication, security groups, NACLs restrict access to authorized users/systems |
| **CC6.7** | Encryption of Data in Transit | IPSec VPN encryption for all inter-region traffic |
| **CC7.1** | System Monitoring | CloudWatch metrics, VPC Flow Logs, VPN connection status monitoring |
| **CC7.2** | Monitoring & Alerting | CloudWatch alarms for VPN connection failures, unusual traffic patterns |
| **A1.3** | Availability Monitoring | VPN redundancy monitoring, connection state tracking |
| **PI1.1** | Processing Integrity | Encrypted data transmission prevents unauthorized modification in transit |

---

## Security Best Practices Implemented

✅ **Encryption in Transit**
- IPSec encryption for all VPN traffic
- Phase 1 & Phase 2 encryption algorithms (AES-256, SHA-2)

✅ **Access Controls**
- Security groups restrict traffic to VPN endpoints
- Network ACLs provide additional layer of filtering
- VPC isolation between regions

✅ **Logging & Monitoring**
- VPC Flow Logs capture all network traffic
- CloudTrail logs all API calls for audit trail
- CloudWatch metrics track VPN connection status
- CloudWatch Logs for centralized log aggregation

✅ **Network Segmentation**
- Separate subnets for VPN resources
- CIDR blocks prevent IP conflicts across regions

✅ **Tagging & Resource Management**
- Consistent resource naming with `carl` prefix
- Environment tags (`prod`) for lifecycle management
- Cost allocation tags for billing tracking

---

## Additional Recommendations

### High Priority
- **AWS GuardDuty**: Enable threat detection for VPN endpoints and network anomalies
- **AWS Config**: Monitor VPN configuration compliance and detect unauthorized changes
- **VPN Connection Redundancy**: Deploy multiple VPN connections per region for HA
- **Customer Gateway Failover**: Implement redundant on-premises VPN endpoints

### Medium Priority
- **AWS Systems Manager Session Manager**: Secure access to EC2 instances without SSH keys
- **VPC Endpoint Policies**: Restrict S3/DynamoDB access through VPN only
- **Network Firewall**: Stateful firewall rules for additional inspection
- **Secrets Manager**: Rotate VPN pre-shared keys programmatically

### Compliance & Auditing
- **AWS Security Hub**: Centralized security findings and compliance status
- **CloudWatch Insights**: Query VPC Flow Logs for security investigations
- **EventBridge**: Automated response to VPN connection failures
- **SNS Notifications**: Real-time alerts for critical VPN events

---

## Prerequisites

### AWS Account Requirements
- Permissions: `ec2:*`, `logs:*`, `cloudwatch:*`, `cloudtrail:*`
- Minimum IAM policy: `AmazonVPCFullAccess`, `CloudWatchLogsFullAccess`
- Multi-region access enabled

### Local Environment
- **Terraform**: v1.0 or higher
- **AWS CLI**: v2.0 or higher (for credential configuration)
- **Credentials**: AWS access key ID and secret access key configured via `~/.aws/credentials` or environment variables

### Network Requirements
- Customer Gateway IP address(es) (on-premises VPN endpoint)
- Pre-shared key (PSK) for VPN authentication
- Existing VPCs in target regions (this solution assumes VPCs already exist)
- No overlapping CIDR blocks between regions

### Documentation
- AWS VPN documentation: https://docs.aws.amazon.com/vpn/
- Terraform AWS Provider: https://registry.terraform.io/providers/hashicorp/aws/latest/docs

---

## Usage Instructions

### 1. Initialize Terraform

```bash
terraform init
```

This downloads the AWS provider and initializes the working directory.

### 2. Review Configuration

```bash
terraform plan -out=tfplan
```

Review the planned resources before deployment. Verify:
- Correct regions are targeted
- VPC CIDRs don't conflict
- VPN endpoints are properly configured

### 3. Deploy Infrastructure

```bash
terraform apply tfplan
```

Deployment typically takes 5-10 minutes. Monitor the output for:
- VPN Connection IDs
- Customer Gateway IDs
- Virtual Private Gateway IDs

### 4. Retrieve Configuration Files

```bash
terraform output vpn_config
```

Download the VPN configuration file for your customer gateway (on-premises VPN device).

### 5. Destroy Infrastructure (if needed)

```bash
terraform destroy
```

⚠️ **Warning**: This permanently deletes all VPN connections and associated resources.

---

## Resources Created

| Resource | Count | Purpose |
|----------|-------|---------|
| Virtual Private Gateway | 2+ | VPN endpoint in each region |
| Customer Gateway | 1+ | On-premises VPN endpoint reference |
| VPN Connection | 2+ | IPSec tunnel between regions |
| VPC Flow Logs | 2+ | Network traffic logging per region |
| CloudWatch Log Group | 2+ | Centralized logging for VPC Flow Logs |
| CloudWatch Alarms | 4+ | VPN connection state and traffic monitoring |
| Security Groups | 2+ | Restrict traffic to VPN resources |
| IAM Role | 1 | CloudWatch Logs permissions |
| CloudTrail | 1 | API audit logging (if enabled) |

---

## Inputs

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `vpc_cidr` | string | `10.0.0.0/16` | CIDR block for primary VPC |
| `resource_prefix` | string | `carl` | Prefix for all resource names |
| `environment` | string | `prod` | Environment name (prod/staging/dev) |
| `regions` | list(string) | `["us-east-1", "us-west-2"]` | AWS regions for VPN deployment |
| `customer_gateway_ip` | string | `` | Public IP of on-premises VPN endpoint |
| `customer_gateway_asn` | number | `65000` | BGP ASN for customer gateway |
| `vpn_preshared_key` | string | `` | Pre-shared key for VPN authentication |
| `enable_cloudtrail` | bool | `true` | Enable CloudTrail for API logging |
| `enable_flow_logs` | bool | `true` | Enable VPC Flow Logs |
| `log_retention_days` | number | `30` | CloudWatch Logs retention period |
| `tags` | map(string) | `{}` | Additional tags for all resources |

---

## Outputs

| Output | Description |
|--------|-------------|
| `vpn_connection_ids` | Map of VPN Connection IDs by region |
| `customer_gateway_id` | Customer Gateway ID |
| `virtual_private_gateway_ids` | Map of Virtual Private Gateway IDs by region |
| `vpn_config_download_url` | URL to download VPN configuration file |
| `cloudwatch_log_group_names` | CloudWatch Log Group names for VPC Flow Logs |
| `security_group_ids` | Security Group IDs for VPN resources |
| `vpc_flow_logs_role_arn` | IAM Role ARN for VPC Flow Logs |

---

## Post-Deployment Steps

### 1. Configure Customer Gateway (On-Premises)

```bash
# Download VPN configuration
terraform output vpn_config_download_url

# Import configuration into your VPN device (Cisco, Juniper, Palo Alto, etc.)
# Follow vendor-specific instructions for IPSec tunnel setup
```

### 2. Verify VPN Connection Status

```bash
# Check VPN connection state
aws ec2 describe-vpn-connections \
  --vpn-connection-ids $(terraform output -raw vpn_connection_ids) \
  --region us-east-1

# Expected state: "available"
# Tunnel status: "UP"
```

### 3. Test Connectivity

```bash
# From an EC2 instance in Region 1, ping an instance in Region 2
ping <instance-ip-region-2>

# Verify traffic flows through VPN (check VPC Flow Logs)
aws logs tail /aws/vpc/flowlogs/carl-prod --follow
```

### 4. Configure CloudWatch Alarms

```bash
# Review alarm thresholds
terraform output cloudwatch_alarm_names

# Adjust thresholds based on your traffic patterns
# Recommended: SNS topic for critical alerts
```

### 5. Enable Advanced Monitoring

```bash
# Enable GuardDuty for threat detection
aws guardduty create-detector --enable --region us-east-1

# Enable AWS Config for compliance monitoring
aws configservice put-config-recorder --config-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/config-role

# Enable Security Hub for centralized findings
aws securityhub enable-security-hub --region us-east-1
```

### 6. Review Logs & Audit Trail

```bash
# Query VPC Flow Logs for security analysis
aws logs start-query \
  --log-group-name /aws/vpc/flowlogs/carl-prod \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcaddr, dstaddr, action | stats count() by action'

# Review CloudTrail for API changes
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=carl-prod-vpn
```

### 7. Document VPN Configuration

- Record Customer Gateway IP and ASN
- Document pre-shared key storage location (use AWS Secrets Manager)
- Create runbook for VPN troubleshooting
- Schedule quarterly security reviews

### 8. Set Up Backup & Disaster Recovery

```bash
# Export VPN configuration
terraform state pull > terraform.tfstate.backup

# Store in secure location (S3 with encryption, version control)
aws s3 cp terraform.tfstate.backup s3://your-backup-bucket/vpn-config/ \
  --sse AES256 --region us-east-1
```

---

## Troubleshooting

### VPN Connection Status: "DOWN"

1. Verify customer gateway IP is reachable
2. Check pre-shared key matches on both ends
3. Verify security group allows UDP 500 and 4500
4. Review CloudWatch Logs for error messages

### No Traffic Flowing Through VPN

1. Confirm route tables include VPN routes
2. Verify security groups allow traffic between regions
3. Check VPC Flow Logs for dropped packets
4. Validate customer gateway configuration

### High Latency or Packet Loss

1. Monitor CloudWatch metrics for tunnel status
2. Check for DPD (Dead Peer Detection) timeouts
3. Review on-premises VPN device logs
4. Consider enabling VPN acceleration

---

## Support & Compliance

For SOC 2 compliance questions or security concerns, contact your security team or AWS Support.

**Compliance Review Checklist:**
- [ ] VPN encryption enabled (IPSec)
- [ ] Logging enabled (VPC Flow Logs, CloudTrail)
- [ ] Monitoring configured (CloudWatch alarms)
- [ ] Access controls validated (security groups, NACLs)
- [ ] Incident response plan documented
- [ ] Annual security assessment completed