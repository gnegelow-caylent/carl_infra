```hcl
# ============================================================================
# General Configuration Variables
# ============================================================================

variable "resource_prefix" {
  description = "Prefix for naming all AWS resources"
  type        = string
  default     = "carl"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.resource_prefix))
    error_message = "Resource prefix must be lowercase alphanumeric and hyphens, max 20 characters"
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Environment = "prod"
    ManagedBy   = "CARL"
  }
}

# ============================================================================
# AWS Region Configuration
# ============================================================================

variable "aws_regions" {
  description = "List of AWS regions for multi-region VPN deployment"
  type        = list(string)
  default     = ["us-east-1", "eu-west-1"]

  validation {
    condition     = length(var.aws_regions) >= 2
    error_message = "Multi-region VPN requires at least 2 regions"
  }
}

variable "primary_region" {
  description = "Primary AWS region for VPN hub"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.primary_region))
    error_message = "Primary region must be a valid AWS region format"
  }
}

# ============================================================================
# VPC and Networking Configuration
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block"
  }
}

variable "vpc_cidr_secondary" {
  description = "Secondary CIDR block for multi-region VPC"
  type        = string
  default     = "10.1.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr_secondary, 0))
    error_message = "Secondary VPC CIDR must be a valid CIDR block"
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring and compliance"
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

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

# ============================================================================
# VPN Configuration
# ============================================================================

variable "vpn_type" {
  description = "Type of VPN solution (site-to-site or client-vpn)"
  type        = string
  default     = "site-to-site"

  validation {
    condition     = contains(["site-to-site", "client-vpn"], var.vpn_type)
    error_message = "VPN type must be site-to-site or client-vpn"
  }
}

variable "vpn_gateway_asn" {
  description = "BGP ASN for VPN Gateway"
  type        = number
  default     = 64512

  validation {
    condition     = var.vpn_gateway_asn >= 64512 && var.vpn_gateway_asn <= 65534
    error_message = "VPN Gateway ASN must be in private range (64512-65534)"
  }
}

variable "customer_gateway_ip" {
  description = "Public IP address of customer gateway for site-to-site VPN"
  type        = string
  default     = ""
}

variable "customer_gateway_bgp_asn" {
  description = "BGP ASN for customer gateway"
  type        = number
  default     = 65000

  validation {
    condition     = var.customer_gateway_bgp_asn >= 64512 && var.customer_gateway_bgp_asn <= 65534
    error_message = "Customer Gateway ASN must be in private range (64512-65534)"
  }
}

variable "vpn_connection_static_routes" {
  description = "Static routes for VPN connection"
  type        = list(string)
  default     = []
}

variable "enable_vpn_acceleration" {
  description = "Enable VPN acceleration for improved performance"
  type        = bool
  default     = true
}

variable "vpn_tunnel_options" {
  description = "VPN tunnel configuration options"
  type = object({
    tunnel1_preshared_key = string
    tunnel2_preshared_key = string
    phase1_encryption     = list(string)
    phase2_encryption     = list(string)
  })
  default = {
    tunnel1_preshared_key = ""
    tunnel2_preshared_key = ""
    phase1_encryption     = ["AES128", "AES256"]
    phase2_encryption     = ["AES128", "AES256"]
  }
}

# ============================================================================
# Monitoring and Logging Configuration
# ============================================================================

variable "enable_cloudwatch_logs" {
  description = "Enable CloudWatch Logs for VPN connections"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention value"
  }
}

variable "enable_vpn_connection_logging" {
  description = "Enable detailed VPN connection logging"
  type        = bool
  default     = true
}

# ============================================================================
# Security Configuration
# ============================================================================

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for VPN-related resources"
  type        = bool
  default     = true
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 10

  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days"
  }
}

variable "enable_security_group_logging" {
  description = "Enable security group change logging"
  type        = bool
  default     = true
}

variable "allowed_vpn_traffic_cidrs" {
  description = "CIDR blocks allowed for VPN traffic"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ============================================================================
# High Availability Configuration
# ============================================================================

variable "enable_multi_az" {
  description = "Enable Multi-AZ deployment for high availability"
  type        = bool
  default     = true
}

variable "enable_nat_gateway_redundancy" {
  description = "Deploy NAT Gateways in multiple AZs for redundancy"
  type        = bool
  default     = true
}

# ============================================================================
# Tagging Strategy
# ============================================================================

variable "cost_center" {
  description = "Cost center for billing and cost allocation"
  type        = string
  default     = "infrastructure"
}

variable "compliance_scope" {
  description = "Compliance scope (SOC2, PCI-DSS, HIPAA, etc.)"
  type        = list(string)
  default     = ["SOC2"]
}
```