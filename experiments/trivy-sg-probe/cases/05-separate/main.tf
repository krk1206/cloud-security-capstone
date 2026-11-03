provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "clean" {
  name        = "separate-sg"
  description = "No inline ingress blocks"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh_open" {
  security_group_id = aws_security_group.clean.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
