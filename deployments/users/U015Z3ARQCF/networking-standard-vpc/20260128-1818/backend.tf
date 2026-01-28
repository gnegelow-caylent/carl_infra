terraform {
  backend "s3" {
    bucket         = "carl-tfstate-${data.aws_caller_identity.current.account_id}"
    key            = "deployments/users/U015Z3ARQCF/networking-standard-vpc/20260128-1818/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "carl-tfstate-locks"
  }
}
