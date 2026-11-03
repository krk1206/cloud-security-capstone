# Terraform 자체 설정 (패치 정책상 AI 패치가 바꿀 수 없는 파일).
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}
