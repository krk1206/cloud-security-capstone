provider "aws" {
  region = "ap-northeast-2"
}

# SSH 는 승인 출처지만 RDP(3389) 가 전세계 개방 → rdp 서비스 FAIL
resource "aws_security_group" "rdp" {
  name        = "rdp-sg"
  description = "rdp open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
