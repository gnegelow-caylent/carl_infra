# Backend configuration for workloads OU customizations
terraform {
  backend "s3" {
    bucket         = "aft-backend-${var.account_id}"
    key            = "account-customizations/workloads/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aft-backend-lock"
  }
}
