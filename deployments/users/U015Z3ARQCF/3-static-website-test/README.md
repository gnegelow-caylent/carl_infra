# Static Website Infrastructure on AWS

## Overview

This Terraform configuration deploys a secure, scalable infrastructure for hosting 3 static websites using Amazon S3 and CloudFront. Each website is served through a global Content Delivery Network (CDN) with HTTPS encryption, providing low-latency access to users worldwide while maintaining compliance with SOC 2 Trust Service Criteria.

**Key Architecture:**
- 3 S3 buckets (one per website) with static website hosting enabled
- CloudFront distributions for CDN acceleration and HTTPS delivery
- Route 53 DNS records for custom domain routing (optional)
- CloudTrail for audit logging and access tracking
- S3 encryption at rest (SSE-S3 or SSE-KMS)
- S3 access logging for compliance and troubleshooting

**Environment Details:**
- VPC CIDR: 10.3.0.0/16
- Resource Prefix: test
- Environment: dev
- Region: us-east-1 (configurable)

---

## SOC 2 Controls Addressed

This infrastructure implements controls supporting the following SOC 2 Trust Service Criteria:

| Control | Implementation | Purpose |
|---------|-----------------|---------|
| **CC6.1** - Logical Access | CloudTrail audit logs track all S3 API calls and CloudFront access | Demonstrates who accessed what resources and when |
| **CC6.6** - Encryption at Rest | S3 SSE-S3 encryption enabled on all buckets | Protects data stored in S3 from unauthorized access |
| **CC6.7** - Encryption in Transit | CloudFront enforces HTTPS/TLS 1.2+ | Protects data in flight between users and CDN |
| **CC7.1** - System Monitoring | CloudTrail logs all API activities; S3 access logs track requests | Enables detection of unauthorized or anomalous access |
| **CC7.2** - Incident Response | CloudTrail provides forensic data for security investigations | Supports root cause analysis and incident response |
| **A1.3** - Availability | CloudFront global edge locations ensure high availability | Automatic failover and geographic redundancy |
| **PI1.1** - Data Processing Integrity | S3 versioning enabled for rollback capability | Prevents accidental or malicious data modification |

---

## Security Best Practices Implemented

✅ **Access Control**
- S3 Block Public Access enabled on all buckets
- CloudFront Origin Access Identity (OAI) restricts direct S3 access
- All traffic routed through CloudFront only

✅ **Encryption**
- Server-Side Encryption (SSE-S3) enabled by default on all S3 buckets
- HTTPS/TLS 1.2+ enforced on CloudFront distributions
- AWS Certificate Manager (ACM) certificates (free, auto-renewed)

✅ **Logging & Monitoring**
- CloudTrail enabled for API audit logs (stored in S3)
- S3 access logging enabled per bucket
- CloudFront access logs available for analysis

✅ **Data Protection**
- S3 versioning enabled for accidental deletion recovery
- MFA Delete protection recommended for production
- Lifecycle policies can archive old versions

✅ **Network Security**
- CloudFront geo-restriction available (optional)
- DDoS protection via AWS Shield Standard (included)

---

## Additional Recommendations

### Immediate (High Priority)
- **AWS Config**: Enable to track S3 bucket configuration compliance
- **CloudWatch Alarms**: Alert on unusual CloudTrail activity or failed requests
- **S3 Bucket Policies**: Explicitly deny unencrypted uploads (`s3:x-amz-server-side-encryption`)

### Short-term (Medium Priority)
- **GuardDuty**: Enable threat detection for unusual API patterns
- **AWS WAF**: Attach to CloudFront for DDoS and bot protection
- **CloudFront Signed URLs**: Implement if content requires access control
- **S3 Object Lock**: Enable for write-once-read-many (WORM) compliance

### Long-term (Enhancement)
- **AWS Inspector**: Scan for configuration vulnerabilities
- **Macie**: Detect sensitive data in S3 buckets
- **Cost Optimization**: Implement S3 Intelligent-Tiering for infrequent access
- **Multi-region Replication**: S3 Cross-Region Replication for disaster recovery

---

## Prerequisites

### AWS Account & Permissions
- AWS account with appropriate IAM permissions:
  - S3 (CreateBucket, PutBucketPolicy, PutBucketLogging, etc.)
  - CloudFront (CreateDistribution)
  - Route 53 (CreateHostedZone, ChangeResourceRecordSets) - if using custom domains
  - CloudTrail (CreateTrail, StartLogging)
  - ACM (RequestCertificate) - if not using existing certificates
  - IAM (CreateRole, PutRolePolicy)

### Local Environment
- **Terraform**: v1.0 or later
- **AWS CLI**: v2.x (optional, for manual verification)
- **Git**: For version control (recommended)

### Domain Names (Optional)
- If using custom domains, ensure Route 53 hosted zones are created or migrated
- Domain registrar access to update nameservers (if not using Route 53 registrar)

### Content
- Static website files (HTML, CSS, JavaScript, images) ready for upload
- Index document name (typically `index.html`)
- Error document name (typically `error.html` or `404.html`)

---

## Usage Instructions

### 1. Initialize Terraform

```bash
terraform init
```

This downloads the required AWS provider and initializes the working directory.

### 2. Review the Plan

```bash
terraform plan -out=tfplan
```

Review the resources that will be created. Verify:
- 3 S3 buckets with correct naming
- CloudFront distributions for each site
- CloudTrail trail creation
- IAM roles and policies

### 3. Apply Configuration

```bash
terraform apply tfplan
```

This creates all resources in your AWS account. Typical deployment time: 5-10 minutes.

### 4. Verify Deployment

```bash
terraform output
```

Capture the CloudFront domain names and S3 bucket names for next steps.

### 5. Upload Website Content

For each website, upload files to the corresponding S3 bucket:

```bash
aws s3 sync ./website1 s3://test-website1-dev --delete
aws s3 sync ./website2 s3://test-website2-dev --delete
aws s3 sync ./website3 s3://test-website3-dev --delete
```

### 6. Configure DNS (Optional)

If using custom domains, create Route 53 CNAME records pointing to CloudFront domains:

```bash
# Example: Point example.com to CloudFront
# In Route 53: CNAME example.com → d123abc.cloudfront.net
```

---

## Resources Created

### S3 Buckets (3)
- `test-website1-dev` - First static website bucket
- `test-website2-dev` - Second static website bucket
- `test-website3-dev` - Third static website bucket
- `test-cloudtrail-logs-dev` - CloudTrail audit log storage

### CloudFront Distributions (3)
- Distribution for website1 with OAI
- Distribution for website2 with OAI
- Distribution for website3 with OAI

### CloudTrail
- Trail: `test-cloudtrail-dev`
- Logs stored in S3 with encryption

### IAM Roles & Policies
- CloudFront Origin Access Identity (OAI) for each distribution
- S3 bucket policies restricting access to OAI only
- CloudTrail service role

### Security & Logging
- S3 access logging enabled per bucket
- CloudTrail API logging enabled
- Block Public Access enabled on all buckets
- SSE-S3 encryption enabled by default

---

## Inputs

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `aws_region` | string | `us-east-1` | AWS region for resource deployment |
| `environment` | string | `dev` | Environment name (dev, staging, prod) |
| `resource_prefix` | string | `test` | Prefix for all resource names |
| `vpc_cidr` | string | `10.3.0.0/16` | VPC CIDR block (informational; not used in this setup) |
| `website_names` | list(string) | `["website1", "website2", "website3"]` | Names of the three static websites |
| `index_document` | string | `index.html` | Default index document for S3 static hosting |
| `error_document` | string | `error.html` | Error document for 4xx/5xx responses |
| `enable_versioning` | bool | `true` | Enable S3 versioning for rollback capability |
| `enable_access_logging` | bool | `true` | Enable S3 access logging |
| `cloudfront_price_class` | string | `PriceClass_100` | CloudFront price class (100, 200, or All) |
| `enable_cloudtrail` | bool | `true` | Enable CloudTrail for audit logging |
| `tags` | map(string) | `{}` | Additional tags for all resources |

---

## Outputs

| Output | Description |
|--------|-------------|
| `s3_bucket_names` | Names of the three S3 buckets created |
| `cloudfront_domain_names` | CloudFront domain names for each website (use for DNS CNAME records) |
| `cloudfront_distribution_ids` | CloudFront distribution IDs for cache invalidation |
| `cloudtrail_s3_bucket` | S3 bucket storing CloudTrail logs |
| `cloudtrail_trail_arn` | ARN of the CloudTrail trail |
| `s3_access_log_buckets` | S3 buckets storing access logs |

---

## Post-Deployment Steps

### 1. Upload Website Content

Upload your static website files to each S3 bucket:

```bash
# Website 1
aws s3 sync ./local/website1 s3://test-website1-dev --delete

# Website 2
aws s3 sync ./local/website2 s3://test-website2-dev --delete

# Website 3
aws s3 sync ./local/website3 s3://test-website3-dev --delete
```

### 2. Test CloudFront Access

```bash
# Test each CloudFront distribution
curl -I https://d123abc.cloudfront.net/index.html
curl -I https://d456def.cloudfront.net/index.html
curl -I https://d789ghi.cloudfront.net/index.html
```

Verify:
- HTTP 200 responses for valid files
- HTTP 403 responses when accessing S3 directly (not through CloudFront)
- HTTPS/TLS 1.2+ in use

### 3. Configure DNS Records (If Using Custom Domains)

In Route 53, create CNAME records:

```
example1.com  CNAME  d123abc.cloudfront.net
example2.com  CNAME  d456def.cloudfront.net
example3.com  CNAME  d789ghi.cloudfront.net
```

Wait for DNS propagation (typically 5-30 minutes).

### 4. Set Up CloudWatch Alarms

Create alarms for:
- CloudFront 4xx/5xx error rates (threshold: >5% of requests)
- CloudTrail API errors
- S3 bucket size growth

Example:
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name test-cloudfront-errors \
  --alarm-description "Alert on high CloudFront error rate" \
  --metric-name 4xxErrorRate \
  --namespace AWS/CloudFront \
  --statistic Average \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold
```

### 5. Review CloudTrail Logs

Verify CloudTrail is logging:

```bash
aws s3 ls s3://test-cloudtrail-logs-dev/
```

Check for recent API calls:

```bash
aws cloudtrail lookup-events --max-results 10
```