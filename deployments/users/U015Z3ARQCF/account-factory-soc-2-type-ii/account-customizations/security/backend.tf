# Backend configuration for security OU customizations
terraform {
  backend "s3" {
    bucket         = "aft-backend-${var.account_id}"
    key            = "account-customizations/security/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aft-backend-lock"
  }
}
