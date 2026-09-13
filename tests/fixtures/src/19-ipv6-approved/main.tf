provider "aws" {
  region = "ap-northeast-2"
}

# IPv6 승인 대역(2001:db8::/32)만 허용 → PASS. IPv4 는 승인 출처.
resource "aws_security_group" "v6ok" {
  name        = "v6-ok-sg"
  description = "ipv6 approved only"

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["10.0.0.0/8"]
    ipv6_cidr_blocks = ["2001:db8::/32"]
  }
}
