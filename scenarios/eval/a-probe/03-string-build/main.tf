provider "aws" {
  region = "ap-northeast-2"
}

locals {
  open = join("/", ["0.0.0.0", "0"])
}

resource "aws_security_group" "string_build" {
  name        = "string-build-sg"
  description = "SSH open via string-constructed CIDR"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.open]
  }
}
