# provider.tf - Terraform 버전과 AWS provider 고정. sg-baseline과 같은 제약(~> 5.0)을 쓴다.
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
  profile = var.aws_profile # 로컬: terraform.tfvars의 "capstone". CI(OIDC): null이면 환경 자격증명 사용

  default_tags {
    tags = {
      Project   = "capstone-2026"
      ManagedBy = "terraform"
      Stack     = "three-tier"
    }
  }
}
