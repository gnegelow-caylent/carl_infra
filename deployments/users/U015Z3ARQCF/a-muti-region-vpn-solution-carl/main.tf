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

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region

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
    Project   = var.resource_prefix
  }
}

# Primary Region - VPC
resource "aws_vpc" "primary" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc-primary"
  }
}

# Primary Region - Subnets
resource "aws_subnet" "primary_public" {
  count                   = 2
  vpc_id                  = aws_vpc.primary.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 2, count.index)
  availability_zone       = data.aws_availability_zones.primary.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-subnet-public-${count.index + 1}"
  }
}

resource "aws_subnet" "primary_private" {
  count             = 2
  vpc_id            = aws_vpc.primary.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 2, count.index + 2)
  availability_zone = data.aws_availability_zones.primary.names[count.index]

  tags = {
    Name = "${local.name_prefix}-subnet-private-${count.index + 1}"
  }
}

# Secondary Region - VPC
resource "aws_vpc" "secondary" {
  provider             = aws.secondary
  cidr_block           = var.secondary_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc-secondary"
  }
}

# Secondary Region - Subnets
resource "aws_subnet" "secondary_public" {
  provider                = aws.secondary
  count                   = 2
  vpc_id                  = aws_vpc.secondary.id
  cidr_block              = cidrsubnet(var.secondary_vpc_cidr, 2, count.index)
  availability_zone       = data.aws_availability_zones.secondary.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-subnet-public-secondary-${count.index + 1}"
  }
}

resource "aws_subnet" "secondary_private" {
  provider          = aws.secondary
  count             = 2
  vpc_id            = aws_vpc.secondary.id
  cidr_block        = cidrsubnet(var.secondary_vpc_cidr, 2, count.index + 2)
  availability_zone = data.aws_availability_zones.secondary.names[count.index]

  tags = {
    Name = "${local.name_prefix}-subnet-private-secondary-${count.index + 1}"
  }
}

# Data sources for availability zones
data "aws_availability_zones" "primary" {
  state = "available"
}

data "aws_availability_zones" "secondary" {
  provider = aws.secondary
  state    = "available"
}

# Primary Region - Internet Gateway
resource "aws_internet_gateway" "primary" {
  vpc_id = aws_vpc.primary.id

  tags = {
    Name = "${local.name_prefix}-igw-primary"
  }
}

# Secondary Region - Internet Gateway
resource "aws_internet_gateway" "secondary" {
  provider = aws.secondary
  vpc_id   = aws_vpc.secondary.id

  tags = {
    Name = "${local.name_prefix}-igw-secondary"
  }
}

# Primary Region - NAT Gateway
resource "aws_eip" "primary_nat" {
  count  = 2
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-eip-nat-primary-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.primary]
}

resource "aws_nat_gateway" "primary" {
  count         = 2
  allocation_id = aws_eip.primary_nat[count.index].id
  subnet_id     = aws_subnet.primary_public[count.index].id

  tags = {
    Name = "${local.name_prefix}-nat-primary-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.primary]
}

# Secondary Region - NAT Gateway
resource "aws_eip" "secondary_nat" {
  provider = aws.secondary
  count    = 2
  domain   = "vpc"

  tags = {
    Name = "${local.name_prefix}-eip-nat-secondary-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.secondary]
}

resource "aws_nat_gateway" "secondary" {
  provider      = aws.secondary
  count         = 2
  allocation_id = aws_eip.secondary_nat[count.index].id
  subnet_id     = aws_subnet.secondary_public[count.index].id

  tags = {
    Name = "${local.name_prefix}-nat-secondary-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.secondary]
}

# Primary Region - Route Tables
resource "aws_route_table" "primary_public" {
  vpc_id = aws_vpc.primary.id

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = aws_internet_gateway.primary.id
  }

  tags = {
    Name = "${local.name_prefix}-rt-public-primary"
  }
}

resource "aws_route_table_association" "primary_public" {
  count          = 2
  subnet_id      = aws_subnet.primary_public[count.index].id
  route_table_id = aws_route_table.primary_public.id
}

resource "aws_route_table" "primary_private" {
  count  = 2
  vpc_id = aws_vpc.primary.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.primary[count.index].id
  }

  tags = {
    Name = "${local.name_prefix}-rt-private-primary-${count.index + 1}"
  }
}

resource "aws_route_table_association" "primary_private" {
  count          = 2
  subnet_id      = aws_subnet.primary_private[count.index].id
  route_table_id = aws_route_table.primary_private[count.index].id
}

# Secondary Region - Route Tables
resource "aws_route_table" "secondary_public" {
  provider = aws.secondary
  vpc_id   = aws_vpc.secondary.id

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = aws_internet_gateway.secondary.id
  }

  tags = {
    Name = "${local.name_prefix}-rt-public-secondary"
  }
}

resource "aws_route_table_association" "secondary_public" {
  provider       = aws.secondary
  count          = 2
  subnet_id      = aws_subnet.secondary_public[count.index].id
  route_table_id = aws_route_table.secondary_public.id
}

resource "aws_route_table" "secondary_private" {
  provider = aws.secondary
  count    = 2
  vpc_id   = aws_vpc.secondary.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.secondary[count.index].id
  }

  tags = {
    Name = "${local.name_prefix}-rt-private-secondary-${count.index + 1}"
  }
}

resource "aws_route_table_association" "secondary_private" {
  provider       = aws.secondary
  count          = 2
  subnet_id      = aws_subnet.secondary_private[count.index].id
  route_table_id = aws_route_table.secondary_private[count.index].id
}

# KMS Key for VPN encryption
resource "aws_kms_key" "vpn" {
  description             = "KMS key for VPN encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-kms-vpn"
  }
}

resource "aws_kms_alias" "vpn" {
  name          = "alias/${local.name_prefix}-vpn"
  target_key_id = aws_kms_key.vpn.key_id
}

# KMS Key for logs encryption
resource "aws_kms_key" "logs" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-kms-logs"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# CloudWatch Log Group for VPN logs
resource "aws_cloudwatch_log_group" "vpn_primary" {
  name              = "/aws/vpn/${local.name_prefix}-primary"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Name = "${local.name_prefix}-log-group-vpn-primary"
  }
}

resource "aws_cloudwatch_log_group" "vpn_secondary" {
  provider          = aws.secondary
  name              = "/aws/vpn/${local.name_prefix}-secondary"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Name = "${local.name_prefix}-log-group-vpn-secondary"
  }
}

# VPC Flow Logs for Primary VPC
resource "aws_flow_log" "primary" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs_primary.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.primary.id

  tags = {
    Name = "${local.name_prefix}-flow-logs-primary"
  }
}

# VPC Flow Logs for Secondary VPC
resource "aws_flow_log" "secondary" {
  provider        = aws.secondary
  iam_role_arn    = aws_iam_role.flow_logs_secondary.arn
  log_destination = aws_cloudwatch_log_group.flow_logs_secondary.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.secondary.id

  tags = {
    Name = "${local.name_prefix}-flow-logs-secondary"
  }
}

# CloudWatch Log Group for VPC Flow Logs - Primary
resource "aws_cloudwatch_log_group" "flow_logs_primary" {
  name              = "/aws/vpc/flowlogs/${local.name_prefix}-primary"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Name = "${local.name_prefix}-log-group-flow-logs-primary"
  }
}

# CloudWatch Log Group for VPC Flow Logs - Secondary
resource "aws_cloudwatch_log_group" "flow_logs_secondary" {
  provider          = aws.secondary
  name              = "/aws/vpc/flowlogs/${local.name_prefix}-secondary"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Name = "${local.name_prefix}-log-group-flow-logs-secondary"
  }
}

# IAM Role for VPC Flow Logs - Primary
resource "aws_iam_role" "flow_logs" {
  name = "${local.name_prefix}-flow-logs-role"

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
    Name = "${local.name_prefix}-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name_prefix}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

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
        Resource = "*"
      }
    ]
  })
}

# IAM Role for VPC Flow Logs - Secondary
resource "aws_iam_role" "flow_logs_secondary" {
  provider = aws.secondary
  name     = "${local.name_prefix}-flow-logs-role-secondary"

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
    Name = "${local.name_prefix}-flow-logs-role-secondary"
  }
}

resource "aws_iam_role_policy" "flow_logs_secondary" {
  provider = aws.secondary
  name     = "${local.name_prefix}-flow-logs-policy-secondary"
  role     = aws_iam_role.flow_logs_secondary.id

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
        Resource = "*"
      }
    ]
  })
}

# Customer Gateway - Primary Region
resource "aws_customer_gateway" "primary" {
  bgp_asn    = var.customer_gateway_bgp_asn
  public_ip  = var.customer_gateway_ip_primary
  type       = "ipsec.1"

  tags = {
    Name = "${local.name_prefix}-cgw-primary"
  }
}

# Customer Gateway - Secondary Region
resource "aws_customer_gateway" "secondary" {
  provider   = aws.secondary
  bgp_asn    = var.customer_gateway_bgp_asn
  public_ip  = var.customer_gateway_ip_secondary
  type       = "ipsec.1"

  tags = {
    Name = "${local.name_prefix}-cgw-secondary"
  }
}

# Virtual Private Gateway - Primary Region
resource "aws_vpn_gateway" "primary" {
  vpc_id            = aws_vpc.primary.id
  type              = "ipsec.1"
  amazon_side_asn   = var.vpn_gateway_asn_primary

  tags = {
    Name = "${local.name_prefix}-vgw-primary"
  }
}

# Virtual Private Gateway - Secondary Region
resource "aws_vpn_gateway" "secondary" {
  provider          = aws.secondary
  vpc_id            = aws_vpc.secondary.id
  type              = "ipsec.1"
  amazon_side_asn   = var.vpn_gateway_asn_secondary

  tags = {
    Name = "${local.name_prefix}-vgw-secondary"
  }
}

# VPN Connection - Primary Region
resource "aws_vpn_connection" "primary" {
  type                       = "ipsec.1"
  customer_gateway_id        = aws_customer_gateway.primary.id
  vpn_gateway_id             = aws_vpn_gateway.primary.id
  static_routes_only         = false
  enable_acceleration        = true
  tunnel1_phase1_encryption_algorithms = ["AES256"]
  tunnel1_phase2_encryption_algorithms = ["AES256"]
  tunnel1_phase1_integrity_algorithms  = ["SHA2-256"]
  tunnel1_phase2_integrity_algorithms  = ["SHA2-256"]
  tunnel1_phase1_dh_group_numbers      = [14]
  tunnel1_phase2_dh_group_numbers      = [14]
  tunnel1_rekey_fuzz_percentage        = 100
  tunnel1_rekey_margin_time_seconds    = 540
  tunnel1_replay_window_size           = 1024
  tunnel1_dpd_action                   = "restart"
  tunnel1_dpd_timeout_action           = "restart"
  tunnel1_dpd_timeout_seconds          = 30
  tunnel1_startup_action               = "start"

  tunnel2_phase1_encryption_algorithms = ["AES256"]
  tunnel2_phase2_encryption_algorithms = ["AES256"]
  tunnel2_phase1_integrity_algorithms  = ["SHA2-256"]
  tunnel2_phase2_integrity_algorithms  = ["SHA2-256"]
  tunnel2_phase1_dh_group_numbers      = [14]
  tunnel2_phase2_dh_group_numbers      = [14]
  tunnel2_rekey_fuzz_percentage        = 100
  tunnel2_rekey_margin_time_seconds    = 540
  tunnel2_replay_window_size           = 1024
  tunnel2_dpd_action                   = "restart"
  tunnel2_dpd_timeout_action           = "restart"
  tunnel2_dpd_timeout_seconds          = 30
  tunnel2_startup_action               = "start"

  tags = {
    Name = "${local.name_prefix}-vpn-connection-primary"
  }
}

# VPN Connection - Secondary Region
resource "aws_vpn_connection" "secondary" {
  provider                             = aws.secondary
  type                                 = "ipsec.1"
  customer_gateway_id                  = aws_customer_gateway.secondary.id
  vpn_gateway_id                       = aws_vpn_gateway.secondary.id
  static_routes_only                   = false
  enable_acceleration                  = true
  tunnel1_phase1_encryption_algorithms = ["AES256"]
  tunnel1_phase2_encryption_algorithms = ["AES256"]
  tunnel1_phase1_integrity_algorithms  = ["SHA2-256"]
  tunnel1_phase2_integrity_algorithms  = ["SHA2-256"]
  tunnel1_phase1_dh_group_numbers      = [14]
  tunnel1_phase2_dh_group_numbers      = [14]
  tunnel1_rekey_fuzz_percentage        = 100
  tunnel1_rekey_margin_time_seconds    = 540
  tunnel1_replay_window_size           = 1024
  tunnel1_dpd_action                   = "restart"
  tunnel1_dpd_timeout_action           = "restart"
  tunnel1_dpd_timeout_seconds          = 30
  tunnel1_startup_action               = "start"

  tunnel2_phase1_encryption_algorithms = ["AES256"]
  tunnel2_phase2_encryption_algorithms = ["AES256"]
  tunnel2_phase1_integrity_algorithms  = ["SHA2-256"]
  tunnel2_phase2_integrity_algorithms  = ["SHA2-256"]
  tunnel2_phase1_dh_group_numbers      = [14]
  tunnel2_phase2_dh_group_numbers      = [14]
  tunnel2_rekey_fuzz_percentage        = 100
  tunnel2_rekey_margin_time_seconds    = 540
  tunnel2_replay_window_size           = 1024
  tunnel2_dpd_action                   = "restart"
  tunnel2_dpd_timeout_action           = "restart"
  tunnel2_dpd_timeout_seconds          = 30
  tunnel2_startup_action               = "start"

  tags = {
    Name = "${local.name_prefix}-vpn-connection-secondary"
  }
}

# VPN Gateway Route Propagation - Primary
resource "aws_vpn_gateway_route_propagation" "primary_private" {
  count          = 2
  vpn_gateway_id = aws_vpn_gateway.primary.id
  route_table_id = aws_route_table.primary_private[count.index].id
}

# VPN Gateway Route Propagation - Secondary
resource "aws_vpn_gateway_route_propagation" "secondary_private" {
  provider       = aws.secondary
  count          = 2
  vpn_gateway_id = aws_vpn_gateway.secondary.id
  route_table_id = aws_route_table.secondary_private[count.index].id
}

# Security Group for VPN - Primary
resource "aws_security_group" "vpn_primary" {
  name        = "${local.name_prefix}-sg-vpn-primary"
  description = "Security group for VPN traffic in primary region"
  vpc_id      = aws_vpc.primary.id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-sg-vpn-primary"
  }
}

# Security Group Rules - Primary VPN
resource "aws_vpc_security_group_ingress_rule" "vpn_primary_ipsec" {
  security_group_id = aws_security_group.vpn_primary.id
  description       = "IPSec traffic from customer gateway"
  from_port         = 500
  to_port           = 500
  ip_protocol       = "udp"
  cidr_ipv4         = var.customer_gateway_ip_primary

  tags = {
    Name = "${local.name_prefix}-sg-rule-ipsec-primary"
  }
}

resource "aws_vpc_security_group_ingress_rule" "vpn_primary_nat_t" {
  security_group_id = aws_security_group.vpn_primary.id
  description       = "NAT-T traffic from customer gateway"
  from_port         = 4500
  to_port           = 4500
  ip_protocol       = "udp"
  cidr_ipv4         = var.customer_gateway_ip_primary

  tags = {
    Name = "${local.name_prefix}-sg-rule-nat-t-primary"
  }
}

resource "aws_vpc_security_group_ingress_rule" "vpn_primary_esp" {
  security_group_id = aws_security_group.vpn_primary.id
  description       = "ESP traffic from customer gateway"
  from_port         = -1
  to_port           = -1
  ip_protocol       = "50"
  cidr_ipv4         = var.customer_gateway_ip_primary

  tags = {
    Name = "${local.name_prefix}-sg-rule-esp-primary"
  }
}

resource "aws_vpc_security_group_egress_rule" "vpn_primary_all" {
  security_group_id = aws_security_group.vpn_primary.id
  description       = "Allow all outbound traffic"
  from_port         = -1
  to_port           = -1
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${local.name_prefix}-sg-rule-egress-all-primary"
  }
}

# Security Group for VPN - Secondary
resource "aws_security_group" "vpn_secondary" {
  provider    = aws.secondary
  name        = "${local.name_prefix}-sg-vpn-secondary"
  description = "Security group for VPN traffic in secondary region"
  vpc_id      = aws_vpc.secondary.id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-sg-vpn-secondary"
  }
}

# Security Group Rules - Secondary VPN
resource "aws_vpc_security_group_ingress_rule" "vpn_secondary_ipsec" {
  provider          = aws.secondary
  security_group_id = aws_security_group.vpn_secondary.id
  description       = "IPSec traffic from customer gateway"
  from_port         = 500
  to_port           = 500
  ip_protocol       = "udp"
  cidr_ipv4         = var.customer_gateway_ip_secondary

  tags = {
    Name = "${local.name_prefix}-sg-rule-ipsec-secondary"
  }
}

resource "aws_vpc_security_group_ingress_rule" "vpn_secondary_nat_t" {
  provider          = aws.secondary
  security_group_id = aws_security_group.vpn_secondary.id
  description       = "NAT-T traffic from customer gateway"
  from_port         = 4500
  to_port           = 4500
  ip_protocol       = "udp"
  cidr_ipv4         = var.customer_gateway_ip_secondary

  tags = {
    Name = "${local.name_prefix}-sg-rule-nat-t-secondary"
  }
}

resource "aws_vpc_security_group_ingress_rule" "vpn_secondary_esp" {
  provider          = aws.secondary
  security_group_id = aws_security_group.vpn_secondary.id
  description       = "ESP traffic from customer gateway"
  from_port         = -1
  to_port           = -1
  ip_protocol       = "50"
  cidr_ipv4         = var.customer_gateway_ip_secondary

  tags = {
    Name = "${local.name_prefix}-sg-rule-esp-secondary"
  }
}

resource "aws_vpc_security_group_egress_rule" "vpn_secondary_all" {
  provider          = aws.secondary
  security_group_id = aws_security_group.vpn_secondary.id
  description       = "Allow all outbound traffic"
  from_port         = -1
  to_port           = -1
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${local.name_prefix}-sg-rule-egress-all-secondary"
  }
}

# CloudWatch Alarms for VPN Connection Status - Primary
resource "aws_cloudwatch_metric_alarm" "vpn_connection_state_primary" {
  alarm_name          = "${local.name_prefix}-vpn-connection-state-primary"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TunnelState"
  namespace           = "AWS/VPN"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alert when VPN tunnel state is down"
  treat_missing_data  = "breaching"

  dimensions = {
    VpnId = aws_vpn_connection.primary.id
  }

  tags = {
    Name = "${local.name_prefix}-alarm-vpn-state-primary"
  }
}

# CloudWatch Alarms for VPN Connection Status - Secondary
resource "aws_cloudwatch_metric_alarm" "vpn_connection_state_secondary" {
  provider            = aws.secondary
  alarm_name          = "${local.name_prefix}-vpn-connection-state-secondary"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TunnelState"
  namespace           = "AWS/VPN"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alert when VPN tunnel state is down"
  treat_missing_data  = "breaching"

  dimensions = {
    VpnId = aws_vpn_connection.secondary.id
  }

  tags = {
    Name = "${local.name_prefix}-alarm-vpn-state-secondary"
  }
}

# CloudWatch Alarms for VPN Tunnel Data In - Primary
resource "aws_cloudwatch_metric_alarm" "vpn_tunnel_data_in_primary" {
  alarm_name          = "${local.name_prefix}-vpn-tunnel-data-in-primary"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 5
  metric_name         = "TunnelDataIn"
  namespace           = "AWS/VPN"
  period              = 300
  statistic           = "Sum"
  threshold           = 1000
  alarm_description   = "Alert when VPN tunnel has minimal data flow"
  treat_missing_data  = "notBreaching"

  dimensions = {
    VpnId = aws_vpn_connection.primary.id
  }