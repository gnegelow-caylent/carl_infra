terraform {
  backend "s3" {
    bucket         = "carl-tfstate-${data.aws_caller_identity.current.account_id}"
    key            = "deployments/users/U015Z3ARQCF/how-should-i-design-an-iot-application-architectur-test/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "carl-tfstate-locks"
  }
}
