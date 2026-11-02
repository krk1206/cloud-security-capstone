provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Tightened SSH access"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "legacy" {
  name        = "legacy-sg"
  description = "Legacy SSH access"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami           = "ami-0c9c942bd7bf113a2"
  instance_type = "t3.micro"

  vpc_security_group_ids = [
    aws_security_group.app.id,
    aws_security_group.legacy.id,
  ]
}
