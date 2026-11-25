terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Same state bucket as cloud-security-baseline, separate key. The bucket
  # name contains the account ID, so it is passed at init time:
  #   terraform init -backend-config="bucket=<state bucket from baseline bootstrap>"
  backend "s3" {
    key          = "aws-detection-as-code/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
    }
  }
}
