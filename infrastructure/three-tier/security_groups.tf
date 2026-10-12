# security_groups.tf - 계층 사이의 허용 경로만 연다.
# 인터넷 --80--> ALB SG --80--> WEB SG --3306--> DB SG
# admin_cidr --22--> Bastion SG --3306--> DB SG
# 규칙을 aws_security_group 안의 ingress/egress 블록이 아니라 별도 리소스로 뺀 이유:
# ALB SG의 egress가 WEB SG를, WEB SG의 ingress가 ALB SG를 가리키면 인라인 방식은 순환 참조가 난다.
# 별도 리소스는 SG를 먼저 전부 만들고 규칙을 나중에 붙이므로 순환이 없다.
# Terraform의 aws_security_group은 기본 "모두 허용 egress"를 제거하므로, 아웃바운드도 필요한 것만 명시한다.

resource "aws_security_group" "alb" {
  name        = "${var.project}-alb-sg"
  description = "ALB: HTTP from internet, to web tier only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project}-alb-sg" }
}

resource "aws_security_group" "web" {
  name        = "${var.project}-web-sg"
  description = "Web tier: HTTP from ALB only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project}-web-sg" }
}

resource "aws_security_group" "bastion" {
  name        = "${var.project}-bastion-sg"
  description = "Bastion: SSH from admin_cidr only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project}-bastion-sg" }
}

resource "aws_security_group" "db" {
  name        = "${var.project}-db-sg"
  description = "RDS MySQL: 3306 from web and bastion only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project}-db-sg" }
}

# ---------- ALB ----------
# 80/tcp를 전 세계에서 받는다. Trivy AWS-0107은 SSH(22)/RDP(3389)/전체 포트만 보므로 80은 finding이 아니다.
resource "aws_vpc_security_group_ingress_rule" "alb_http_in" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_web" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To web tier"
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

# ---------- WEB ----------
resource "aws_vpc_security_group_ingress_rule" "web_from_alb" {
  security_group_id            = aws_security_group.web.id
  description                  = "HTTP from ALB"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "web_to_db" {
  security_group_id            = aws_security_group.web.id
  description                  = "MySQL to db tier"
  referenced_security_group_id = aws_security_group.db.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

# 패키지 설치(dnf, HTTPS)와 SSM Agent 통신을 위한 아웃바운드. NAT Gateway를 거쳐 나간다.
# Trivy AWS-0104(CRITICAL)는 포트와 무관하게 0.0.0.0/0 egress 전체를 잡는다.
# 설계상 필요한 경로이고 목적지 포트를 443으로 제한했으므로 사유를 남기고 예외 처리한다.
# 다음 단계: S3 게이트웨이 엔드포인트 + 프리픽스 리스트로 목적지를 더 좁힌다.
#trivy:ignore:AWS-0104
resource "aws_vpc_security_group_egress_rule" "web_https_out" {
  security_group_id = aws_security_group.web.id
  description       = "HTTPS out via NAT (package install, SSM)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# ---------- BASTION ----------
# SSH는 운영자 공인 IP /32 하나만. 0.0.0.0/0이면 AWS-0107(HIGH)이고 우리 연구의 시나리오 1이 된다.
resource "aws_vpc_security_group_ingress_rule" "bastion_ssh_in" {
  security_group_id = aws_security_group.bastion.id
  description       = "SSH from admin only"
  cidr_ipv4         = var.admin_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "bastion_to_db" {
  security_group_id            = aws_security_group.bastion.id
  description                  = "MySQL client to db tier"
  referenced_security_group_id = aws_security_group.db.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

#trivy:ignore:AWS-0104
resource "aws_vpc_security_group_egress_rule" "bastion_https_out" {
  security_group_id = aws_security_group.bastion.id
  description       = "HTTPS out (package install)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# ---------- DB ----------
# RDS는 연결을 받기만 하므로 egress 규칙이 없다.
resource "aws_vpc_security_group_ingress_rule" "db_from_web" {
  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from web tier"
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_bastion" {
  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from bastion"
  referenced_security_group_id = aws_security_group.bastion.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}
