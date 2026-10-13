provider "aws" {
  region = "ap-northeast-2"
}

# plan 밖의 기존 SG(sg-...)가 같은 인스턴스에 붙어 있다. 그 SG 규칙은 plan 에서 볼 수 없다 → UNKNOWN
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

resource "aws_instance" "app" {
  ami                    = "ami-0c9c942bd7bf113a2"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id, "sg-0123456789abcdef0"]
}
