provider "aws" {
  region = "ap-northeast-2"
}

# plan 시점에 값이 정해지지 않는 CIDR (EIP 의 public_ip) → UNKNOWN
resource "aws_eip" "admin" {
  domain = "vpc"
}

resource "aws_security_group" "eip_sg" {
  name        = "eip-sg"
  description = "ssh from an eip allocated at apply time"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_eip.admin.public_ip}/32"]
  }
}
