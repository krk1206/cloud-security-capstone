# AWS provider — 자격증명은 여기 적지 않는다 (환경변수로만). 별칭 provider 없음 (오프라인 plan 은 기본 provider 하나에만 가짜 자격증명을 넣는다).
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
    }
  }
}
