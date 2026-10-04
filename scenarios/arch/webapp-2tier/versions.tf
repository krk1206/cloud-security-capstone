# Terraform 자체 설정. 이 파일은 패치 정책(policy/patch_policy.json protected_file_names)상 AI 패치가 건드릴 수 없다.
terraform {
  # 팀 PC 는 Terraform 1.16.1, 개발 환경은 OpenTofu 1.10.6 — 둘 다 1.5 이상이면 된다.
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 버전을 못 박는 이유(D-15, 2026-09-29 실측): 안 박으면 init 시점의 최신(6.x)이 받아지고, 6.x 는 리소스마다
      # region 속성을 plan 에 넣어 "원본 plan ↔ 패치 plan" 비교(V5)가 패치와 무관한 차이를 잡는다.
      version = "5.100.0"
    }
  }
}
