provider "aws" {
  region = "ap-northeast-2"
}

# ICMP 만 전세계 허용. tcp/22 서비스와 무관 → ssh 판정 PASS (icmp 는 이 intent 의 보호 대상이 아님)
resource "aws_security_group" "icmp" {
  name        = "icmp-sg"
  description = "ping from anywhere, ssh from approved"

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
