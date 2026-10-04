provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "baseline" {
  name        = "baseline-sg"
  description = "Baseline: SSH open to the world"
}
