provider "aws" {
  region = "ap-northeast-2"
}

# 00-baseline 의 정상 수정본: SSH 를 승인 출처(테스트 intent 기준 10.0.0.0/8)로만 허용
resource "aws_security_group" "baseline" {
  name        = "baseline-sg"
  description = "Baseline fixed: SSH only from approved source"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
