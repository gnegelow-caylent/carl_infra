# Backend configuration
terraform {
  backend "s3" {
    bucket         = "aft-backend-${var.organization_id}"
    key            = "global-customizations/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aft-backend-lock"
  }
}
