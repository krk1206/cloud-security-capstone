provider "aws" {
  region = "ap-northeast-2"
}

variable "cidr" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

resource "aws_security_group" "var_default" {
  name        = "var-default-sg"
  description = "SSH open via variable default"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.cidr
  }
}
