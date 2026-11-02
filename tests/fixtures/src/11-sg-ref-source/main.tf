provider "aws" {
  region = "ap-northeast-2"
}

# 참조 SG 출처. bastion SG 자체는 22 를 전세계에 열어두었지만, app 의 출처는 "bastion SG 가 붙은 ENI" 이지
# bastion 의 인바운드 규칙을 상속하는 것이 아니다. app 판정은 승인 목록에 bastion 참조가 있는지로만 정한다.
resource "aws_security_group" "bastion" {
  name        = "bastion-sg"
  description = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "app reachable only via bastion"

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
}
