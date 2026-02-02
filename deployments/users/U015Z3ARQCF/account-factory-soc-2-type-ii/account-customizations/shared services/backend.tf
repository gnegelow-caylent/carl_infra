# Backend configuration for shared services OU customizations
terraform {
  backend "s3" {
    bucket         = "aft-backend-${var.account_id}"
    key            = "account-customizations/shared services/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aft-backend-lock"
  }
}
