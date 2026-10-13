provider "aws" {
  region = "ap-northeast-2"
}

# 포트 범위 20-25 가 22 를 덮는다 (부분 범위 규칙). 승인 출처 규칙도 함께 있음
resource "aws_security_group" "partial" {
  name        = "partial-range-sg"
  description = "range rule covers ssh"

  ingress {
    description = "approved ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    description = "ftp-ish range that also covers 22"
    from_port   = 20
    to_port     = 25
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
