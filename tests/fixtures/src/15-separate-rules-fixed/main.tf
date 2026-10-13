provider "aws" {
  region = "ap-northeast-2"
}

# inline ingress 없이 별도 규칙 리소스로 승인 출처만 허용 (정상). inline ingress 는 provider computed → caveat
resource "aws_security_group" "clean" {
  name        = "separate-fixed-sg"
  description = "rules in separate resources"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_approved" {
  security_group_id = aws_security_group.clean.id
  cidr_ipv4         = "10.0.0.0/8"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
