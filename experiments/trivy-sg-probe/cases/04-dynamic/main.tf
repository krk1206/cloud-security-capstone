provider "aws" {
  region = "ap-northeast-2"
}

variable "rules" {
  type = list(object({
    port = number
    cidr = string
  }))
  default = [
    {
      port = 22
      cidr = "0.0.0.0/0"
    }
  ]
}

resource "aws_security_group" "dynamic_rules" {
  name        = "dynamic-sg"
  description = "SSH open via dynamic ingress block"

  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = [ingress.value.cidr]
    }
  }
}
