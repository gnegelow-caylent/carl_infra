terraform {
  backend "s3" {
    bucket         = "carl-tfstate-${data.aws_caller_identity.current.account_id}"
    key            = "deployments/users/U015Z3ARQCF/i-want-a-multi-az-rds-instance-with-a-transit-gate-carl/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "carl-tfstate-locks"
  }
}
