variable "aws_region" {
  description = "AWS region to deploy resources in."
  type        = string
}

provider "aws" {
  region = var.aws_region
}
