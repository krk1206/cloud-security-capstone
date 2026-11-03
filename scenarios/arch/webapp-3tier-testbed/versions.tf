# 2차 검사(V7·V8)용 축소 시험 환경. scenarios/arch/webapp-3tier 와 보안 그룹 파일(security_groups.tf)이 바이트 단위로 같다.
# 이 폴더는 사람이 terraform apply / destroy 한다. 프로그램은 상태 읽기(terraform show -json)·AWS 조회·접속 시험만 한다.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Purpose   = "iacpatch-testbed"
      Owner     = "B"
    }
  }
}
