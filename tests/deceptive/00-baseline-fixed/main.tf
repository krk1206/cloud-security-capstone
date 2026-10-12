provider "aws" {
  region = "ap-northeast-2"
}

# 00-baseline에 대한 "정당한" 패치 결과. 승인 CIDR(policy/approved_cidrs 예시 값)로만 교체.
# V6는 이 상태를 NOT_EXPOSED로 판정해야 한다 (오탐 없음 기준).
resource "aws_security_group" "baseline" {
  name        = "baseline-sg"
  description = "Baseline: SSH restricted to approved operator address"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.10/32"]
  }
}
