terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = "capstone"

  default_tags {
    tags = {
      Project   = "capstone-2026"
      ManagedBy = "terraform"
      Purpose   = "security-research"
    }
  }
}
