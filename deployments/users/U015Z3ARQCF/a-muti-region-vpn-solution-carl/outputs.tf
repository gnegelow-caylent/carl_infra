```hcl
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "public_subnet_cidrs" {
  description = "List of public subnet CIDR blocks"
  value       = aws_subnet.public[*].cidr_block
}

output "private_subnet_cidrs" {
  description = "List of private subnet CIDR blocks"
  value       = aws_subnet.private[*].cidr_block
}

output "vpc_security_group_id" {
  description = "The ID of the VPC security group"
  value       = aws_security_group.vpc.id
}

output "vpn_security_group_id" {
  description = "The ID of the VPN security group"
  value       = aws_security_group.vpn.id
}

output "vpn_endpoint_ids" {
  description = "Map of VPN endpoint IDs by region"
  value       = { for region, endpoint in aws_ec2_client_vpn_endpoint.main : region => endpoint.id }
}

output "vpn_endpoint_arns" {
  description = "Map of VPN endpoint ARNs by region"
  value       = { for region, endpoint in aws_ec2_client_vpn_endpoint.main : region => endpoint.arn }
}

output "vpn_endpoint_dns_names" {
  description = "Map of VPN endpoint DNS names by region"
  value       = { for region, endpoint in aws_ec2_client_vpn_endpoint.main : region => endpoint.dns_name }
}

output "vpn_certificate_arn" {
  description = "ARN of the VPN server certificate"
  value       = aws_acm_certificate.vpn_server.arn
  sensitive   = true
}

output "vpn_client_certificate_arn" {
  description = "ARN of the VPN client certificate"
  value       = aws_acm_certificate.vpn_client.arn
  sensitive   = true
}

output "vpn_kms_key_id" {
  description = "ID of the KMS key used for VPN encryption"
  value       = aws_kms_key.vpn.id
}

output "vpn_kms_key_arn" {
  description = "ARN of the KMS key used for VPN encryption"
  value       = aws_kms_key.vpn.arn
}

output "vpn_kms_key_alias" {
  description = "Alias of the KMS key used for VPN encryption"
  value       = aws_kms_alias.vpn.name
}

output "vpn_client_vpn_authorization_rule_ids" {
  description = "Map of VPN authorization rule IDs by region"
  value       = { for region, rule in aws_ec2_client_vpn_authorization_rule.main : region => rule.id }
}

output "vpn_client_vpn_network_association_ids" {
  description = "Map of VPN network association IDs by region and subnet"
  value       = { for key, assoc in aws_ec2_client_vpn_network_association.main : key => assoc.id }
}

output "vpn_client_vpn_route_ids" {
  description = "Map of VPN route IDs by region"
  value       = { for region, route in aws_ec2_client_vpn_route.main : region => route.id }
}

output "internet_gateway_id" {
  description = "The ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

output "nat_gateway_public_ips" {
  description = "List of NAT Gateway public IP addresses"
  value       = aws_nat_gateway.main[*].public_ip
}

output "elastic_ip_ids" {
  description = "List of Elastic IP IDs for NAT Gateways"
  value       = aws_eip.nat[*].id
}

output "public_route_table_id" {
  description = "The ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_ids" {
  description = "List of private route table IDs"
  value       = aws_route_table.private[*].id
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for VPN"
  value       = aws_cloudwatch_log_group.vpn.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for VPN"
  value       = aws_cloudwatch_log_group.vpn.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for VPN client configuration"
  value       = aws_s3_bucket.vpn_config.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for VPN client configuration"
  value       = aws_s3_bucket.vpn_config.arn
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "resource_prefix" {
  description = "Resource prefix for all created resources"
  value       = var.resource_prefix
}

output "aws_regions" {
  description = "List of AWS regions where VPN endpoints are deployed"
  value       = var.aws_regions
}

output "vpc_flow_logs_role_arn" {
  description = "ARN of the IAM role for VPC Flow Logs"
  value       = aws_iam_role.vpc_flow_logs.arn
}

output "vpc_flow_logs_group_name" {
  description = "Name of the CloudWatch log group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}

output "vpc_flow_logs_group_arn" {
  description = "ARN of the CloudWatch log group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.arn
}
```