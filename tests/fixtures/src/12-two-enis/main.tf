provider "aws" {
  region = "ap-northeast-2"
}

# 서로 다른 인스턴스(ENI)에 붙은 SG 는 섞지 않는다. app 인스턴스는 승인 출처만, legacy 인스턴스는 개방.
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "app"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "legacy" {
  name        = "legacy-sg"
  description = "legacy"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami                    = "ami-0c9c942bd7bf113a2"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id]
}

resource "aws_instance" "legacy" {
  ami                    = "ami-0c9c942bd7bf113a2"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.legacy.id]
}
