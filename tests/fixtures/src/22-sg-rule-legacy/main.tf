provider "aws" {
  region = "ap-northeast-2"
}

# 구형 aws_security_group_rule 리소스로 개방 (type=ingress)
resource "aws_security_group" "legacy_rule" {
  name        = "legacy-rule-sg"
  description = "rule via aws_security_group_rule"
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy_rule.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/1", "128.0.0.0/1"]
}
