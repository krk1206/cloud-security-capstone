provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "cidr_split" {
  name        = "cidr-split-sg"
  description = "SSH open via two halves of the address space"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]
  }
}
