terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Fylles ut etter at bootstrap er kjørt (docs/PLAN.md Fase 2).
  # Kjør deretter: terraform init -migrate-state
  backend "s3" {
    bucket         = "tfstate-cloudsec-khalid-7291"
    key            = "cloud-sec-baseline/dev/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "tfstate-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-cloud-security-baseline"
      ManagedBy   = "terraform"
      Environment = "dev"
    }
  }
}
