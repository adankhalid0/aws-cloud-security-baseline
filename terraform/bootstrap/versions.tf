terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Bootstrap has no remote backend yet -- it CREATES the backend.
  # State for this tiny stack is kept local on purpose (see docs/PLAN.md, Fase 2).
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "aws-cloud-security-baseline"
      ManagedBy = "terraform"
      Component = "bootstrap"
    }
  }
}
