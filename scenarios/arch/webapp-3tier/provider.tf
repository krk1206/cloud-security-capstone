# AWS provider — "어느 계정의 어느 리전에 만들 것인가". 자격증명(액세스 키)은 여기 적지 않는다 (환경변수로만).
# 이 파일은 protected_file_names 에 들어 있어 AI 패치가 바꿀 수 없다.
# 별칭(alias) provider 를 두지 않는다 — 검증 파이프라인의 오프라인 plan 이 기본 provider 하나에만 가짜 자격증명을 넣기 때문.
# 그래서 WAF 는 CloudFront(us-east-1 전용)가 아니라 ALB 에 붙는 리전 WAF 로 둔다 (edge.tf).
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Owner     = "B"
    }
  }
}
