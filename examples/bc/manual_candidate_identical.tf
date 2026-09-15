resource "aws_security_group" "vulnerable_ssh" {
  name        = "capstone-vuln-ssh"
  description = "Intentionally misconfigured for capstone research"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH open to the world (intentional defect)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
