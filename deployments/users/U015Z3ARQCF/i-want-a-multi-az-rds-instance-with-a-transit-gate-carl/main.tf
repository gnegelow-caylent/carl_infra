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
  name_prefix = "carl-${var.environment}"
  common_tags = {
    Name      = local.name_prefix
    Environment = var.environment
    ManagedBy = "Terraform"
    Project   = "CARL"
  }
}

# Data source for default VPC
data "aws_vpc" "default" {
  default = true
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# KMS key for RDS encryption (CC6.7 - Encryption at rest)
resource "aws_kms_key" "rds" {
  description             = "${local.name_prefix}-rds-encryption-key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# DB Subnet Group for Multi-AZ deployment
resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-db-subnet-group"
    }
  )
}

# VPC for RDS infrastructure
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-vpc"
    }
  )
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-igw"
    }
  )
}

# Public Subnets (for NAT Gateway)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 2, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-public-subnet-${count.index + 1}"
      Type = "Public"
    }
  )
}

# Private Subnets (for RDS)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 2, count.index + 2)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-private-subnet-${count.index + 1}"
      Type = "Private"
    }
  )
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-nat-eip-${count.index + 1}"
    }
  )

  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways for private subnet internet access
resource "aws_nat_gateway" "main" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-nat-gateway-${count.index + 1}"
    }
  )

  depends_on = [aws_internet_gateway.main]
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = aws_internet_gateway.main.id
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-public-rt"
    }
  )
}

# Route table associations for public subnets
resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Route tables for private subnets (one per AZ for NAT Gateway)
resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-private-rt-${count.index + 1}"
    }
  )
}

# Route table associations for private subnets
resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# VPC Flow Logs for monitoring (CC7.2 - Monitoring)
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-vpc-flow-logs"
    }
  )
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flowlogs/${local.name_prefix}"
  retention_in_days = 30

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-vpc-flow-logs-group"
    }
  )
}

# IAM Role for VPC Flow Logs
resource "aws_iam_role" "vpc_flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-role"

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

  tags = local.common_tags
}

# IAM Policy for VPC Flow Logs
resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-policy"
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
        Resource = "*"
      }
    ]
  })
}

# Security Group for RDS (CC6.1 - Logical Access Control)
resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds-sg"
    }
  )
}

# Security Group Rule - Ingress (restrict to application layer)
resource "aws_vpc_security_group_ingress_rule" "rds_mysql" {
  security_group_id = aws_security_group.rds.id

  description = "MySQL access from within VPC"
  from_port   = 3306
  to_port     = 3306
  ip_protocol = "tcp"
  cidr_ipv4   = var.vpc_cidr

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds-ingress-mysql"
    }
  )
}

# Security Group Rule - Egress (least privilege)
resource "aws_vpc_security_group_egress_rule" "rds" {
  security_group_id = aws_security_group.rds.id

  description = "Allow all outbound traffic"
  from_port   = 0
  to_port     = 0
  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds-egress"
    }
  )
}

# CloudWatch Log Group for RDS Enhanced Monitoring
resource "aws_cloudwatch_log_group" "rds_enhanced_monitoring" {
  name              = "/aws/rds/instance/${local.name_prefix}/enhanced-monitoring"
  retention_in_days = 30

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds-enhanced-monitoring"
    }
  )
}

# IAM Role for RDS Enhanced Monitoring
resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${local.name_prefix}-rds-enhanced-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Attach AWS managed policy for RDS Enhanced Monitoring
resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# RDS Instance - Multi-AZ with encryption and monitoring
resource "aws_db_instance" "main" {
  identifier     = "${local.name_prefix}-mysql-db"
  engine         = "mysql"
  engine_version = "8.0.35"
  instance_class = var.db_instance_class

  # Storage configuration
  allocated_storage     = var.db_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  # Multi-AZ deployment (CC6.6 - System Boundaries, A1 - Availability)
  multi_az = true

  # Database configuration
  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # Backup configuration (PI1 - Processing Integrity)
  backup_retention_period = 30
  backup_window           = "03:00-04:00"
  copy_tags_to_snapshot   = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "${local.name_prefix}-mysql-db-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  # Maintenance configuration
  maintenance_window = "sun:04:00-sun:05:00"
  auto_minor_version_upgrade = true

  # Logging configuration (CC7.2 - Monitoring)
  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
  log_retention_in_days           = 30

  # Enhanced monitoring (CC7.1 - Threat Detection)
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.rds_enhanced_monitoring.arn
  enable_performance_insights     = true
  performance_insights_retention_period = 7

  # Security and compliance
  deletion_protection = true
  iam_database_authentication_enabled = true

  # Enable automated backups
  backup_window = "03:00-04:00"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-mysql-db"
    }
  )

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    aws_db_subnet_group.main,
    aws_security_group.rds,
    aws_cloudwatch_log_group.rds_enhanced_monitoring
  ]
}

# CloudWatch Alarm for RDS CPU Utilization (CC7.1 - Threat Detection)
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${local.name_prefix}-rds-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alert when RDS CPU exceeds 80%"
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# CloudWatch Alarm for RDS Database Connections
resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${local.name_prefix}-rds-database-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alert when database connections exceed 80"
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# CloudWatch Alarm for RDS Storage Space
resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${local.name_prefix}-rds-free-storage-space"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 2147483648 # 2GB in bytes
  alarm_description   = "Alert when free storage space is less than 2GB"
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# DB Parameter Group for enhanced security
resource "aws_db_parameter_group" "main" {
  family      = "mysql8.0"
  name        = "${local.name_prefix}-mysql-params"
  description = "Parameter group for ${local.name_prefix} MySQL instance"

  # Enable slow query logging
  parameter {
    name  = "slow_query_log"
    value = "1"
  }

  parameter {
    name  = "long_query_time"
    value = "2"
  }

  # Enable general logging (can be disabled in production for performance)
  parameter {
    name  = "general_log"
    value = "0"
  }

  # Enforce SSL connections
  parameter {
    name  = "require_secure_transport"
    value = "ON"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-mysql-parameter-group"
    }
  )
}

# Update RDS instance to use the parameter group
resource "aws_db_instance" "main" {
  parameter_group_name = aws_db_parameter_group.main.name
}

# RDS Event Subscription for notifications
resource "aws_db_event_subscription" "main" {
  name      = "${local.name_prefix}-rds-events"
  sns_topic = aws_sns_topic.rds_events.arn

  source_type = "db-instance"

  event_categories = [
    "availability",
    "backup",
    "configuration change",
    "deletion",
    "failover",
    "failure",
    "maintenance",
    "recovery"
  ]

  tags = local.common_tags
}

# SNS Topic for RDS Events
resource "aws_sns_topic" "rds_events" {
  name = "${local.name_prefix}-rds-events"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds-events-topic"
    }
  )
}

# SNS Topic Policy for RDS
resource "aws_sns_topic_policy" "rds_events" {
  arn = aws_sns_topic.rds_events.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.rds_events.arn
      }
    ]
  })
}

# DB Snapshot for backup compliance
resource "aws_db_snapshot" "backup" {
  db_instance_identifier = aws_db_instance.main.id
  db_snapshot_identifier = "${local.name_prefix}-mysql-backup-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-mysql-snapshot"
    }
  )

  depends_on = [aws_db_instance.main]
}
```