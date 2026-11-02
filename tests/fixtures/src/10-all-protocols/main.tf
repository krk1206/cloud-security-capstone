provider "aws" {
  region = "ap-northeast-2"
}

# protocol -1 (전체) 로 개방. 포트 필드는 0 이지만 모든 서비스에 해당한다
resource "aws_security_group" "allproto" {
  name        = "all-proto-sg"
  description = "all protocols open"

  ingress {
    description = "everything"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
