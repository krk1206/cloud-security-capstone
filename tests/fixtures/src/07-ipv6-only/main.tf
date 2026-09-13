provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "ipv6_only" {
  name        = "ipv6-only-sg"
  description = "IPv4 restricted, IPv6 wide open"

  ingress {
    description      = "SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["10.0.0.0/8"]
    ipv6_cidr_blocks = ["::/0"]
  }
}
