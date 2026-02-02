# Production-ready VPC with SOC 2 Type II compliance
# Includes public/private subnets, NAT gateways, VPC Flow Logs, and VPC endpoints

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
    tags = {
      ManagedBy  = "CARL"
      Compliance = "SOC2-TypeII"
      Environment = var.environment
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

variable "vpc_name" {
  description = "Name of the VPC"
  type        = string
  default     = "prod-prod"
}

variable "cidr_block" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.3.0.0/16"
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "availability_zones" {
  description = "Number of availability zones"
  type        = number
  default     = 2
  validation {
    condition     = var.availability_zones >= 2 && var.availability_zones <= 3
    error_message = "Must be between 2 and 3 availability zones."
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for SOC 2 compliance"
  type        = bool
  default     = true
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for AWS services"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames in VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Enable DNS support in VPC"
  type        = bool
  default     = true
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (SOC 2 requires 7 years minimum)"
  type        = number
  default     = 2555
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# KMS key for VPC Flow Logs encryption (SOC 2 CC6.1)
resource "aws_kms_key" "vpc_flow_logs" {
  description             = "KMS key for VPC Flow Logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "${var.vpc_name}-flow-logs-key"
  }
}

resource "aws_kms_alias" "vpc_flow_logs" {
  name          = "alias/${var.vpc_name}-flow-logs"
  target_key_id = aws_kms_key.vpc_flow_logs.key_id
}

# CloudWatch Log Group for VPC Flow Logs (SOC 2 CC7.2)
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flowlogs/${var.vpc_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.vpc_flow_logs.arn

  tags = {
    Name = "${var.vpc_name}-flow-logs"
  }
}

# IAM role for VPC Flow Logs
resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.vpc_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.vpc_name}-flow-logs-role"
  }
}

# IAM policy for VPC Flow Logs
resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.vpc_name}-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
      },
      {
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Effect   = "Allow"
        Resource = aws_kms_key.vpc_flow_logs.arn
      }
    ]
  })
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support

  tags = {
    Name = var.vpc_name
  }
}

# VPC Flow Logs (SOC 2 CC7.2, CC7.3)
resource "aws_flow_log" "main" {
  count                   = var.enable_vpc_flow_logs ? 1 : 0
  iam_role_arn            = aws_iam_role.vpc_flow_logs.arn
  log_destination         = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
  traffic_type            = "ALL"
  vpc_id                  = aws_vpc.main.id
  log_destination_type    = "cloud-watch-logs"
  log_format              = "${aws_vpc.main.id} $${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${tcpflags} $${type} $${pkt-srcaddr} $${pkt-dstaddr} $${region} $${vpc-id} $${flow-logs-id} $${traffic-type} $${subnet-id} $${instance-id} $${interface-type} $${eni-id} $${local-gateway-route-table-id} $${vpc-peering-connection-id} $${flow-direction} $${traffic-path} $${packet-aggregation-flags}"
  max_aggregation_interval = 60

  tags = {
    Name = "${var.vpc_name}-flow-logs"
  }

  depends_on = [aws_iam_role_policy.vpc_flow_logs]
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.vpc_name}-igw"
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = var.availability_zones
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.cidr_block, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.vpc_name}-public-${count.index + 1}"
    Type = "Public"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count              = var.availability_zones
  vpc_id             = aws_vpc.main.id
  cidr_block         = cidrsubnet(var.cidr_block, 4, count.index + var.availability_zones)
  availability_zone  = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.vpc_name}-private-${count.index + 1}"
    Type = "Private"
  }
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? var.availability_zones : 0
  domain = "vpc"

  tags = {
    Name = "${var.vpc_name}-eip-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways (one per AZ for HA)
resource "aws_nat_gateway" "main" {
  count         = var.enable_nat_gateway ? var.availability_zones : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.vpc_name}-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.vpc_name}-public-rt"
  }
}

# Public Route Table Associations
resource "aws_route_table_association" "public" {
  count          = var.availability_zones
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Tables (one per AZ for NAT Gateway routing)
resource "aws_route_table" "private" {
  count  = var.availability_zones
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = var.enable_nat_gateway ? aws_nat_gateway.main[count.index].id : null
  }

  tags = {
    Name = "${var.vpc_name}-private-rt-${count.index + 1}"
  }
}

# Private Route Table Associations
resource "aws_route_table_association" "private" {
  count          = var.availability_zones
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Network ACL for additional security (SOC 2 CC6.2)
resource "aws_network_acl" "main" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = concat(aws_subnet.public[*].id, aws_subnet.private[*].id)

  # Allow all inbound traffic (can be restricted based on requirements)
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow all outbound traffic
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "${var.vpc_name}-nacl"
  }
}

# VPC Endpoints for AWS Services (cost optimization and security)
resource "aws_vpc_endpoint" "s3" {
  count           = var.enable_vpc_endpoints ? 1 : 0
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.${data.aws_availability_zones.available.names[0] != "" ? split(".", data.aws_availability_zones.available.names[0])[0] : var.aws_region}.s3"
  route_table_ids = concat(aws_route_table.public[*].id, aws_route_table.private[*].id)

  tags = {
    Name = "${var.vpc_name}-s3-endpoint"
  }
}

# VPC Endpoint for DynamoDB
resource "aws_vpc_endpoint" "dynamodb" {
  count           = var.enable_vpc_endpoints ? 1 : 0
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.${data.aws_availability_zones.available.names[0] != "" ? split(".", data.aws_availability_zones.available.names[0])[0] : var.aws_region}.dynamodb"
  route_table_ids = concat(aws_route_table.public[*].id, aws_route_table.private[*].id)

  tags = {
    Name = "${var.vpc_name}-dynamodb-endpoint"
  }
}

# Security Group for VPC Endpoints (SOC 2 CC6.2)
resource "aws_security_group" "vpc_endpoints" {
  count       = var.enable_vpc_endpoints ? 1 : 0
  name        = "${var.vpc_name}-vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.vpc_name}-vpc-endpoints-sg"
  }
}

# VPC Endpoint for Secrets Manager
resource "aws_vpc_endpoint" "secretsmanager" {
  count               = var.enable_vpc_endpoints ? 1 : 0
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_availability_zones.available.names[0] != "" ? split(".", data.aws_availability_zones.available.names[0])[0] : var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = {
    Name = "${var.vpc_name}-secretsmanager-endpoint"
  }
}

# VPC Endpoint for Systems Manager
resource "aws_vpc_endpoint" "ssm" {
  count               = var.enable_vpc_endpoints ? 1 : 0
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_availability_zones.available.names[0] != "" ? split(".", data.aws_availability_zones.available.names[0])[0] : var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.