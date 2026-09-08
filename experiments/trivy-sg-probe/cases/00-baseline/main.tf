provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "baseline" {
  name        = "baseline-sg"
  description = "Baseline: SSH open to the world"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
