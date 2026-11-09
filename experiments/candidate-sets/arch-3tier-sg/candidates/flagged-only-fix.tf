# 보안 그룹(SG) 층: 계층마다 하나. "어떤 출처(IP 대역 또는 다른 계층의 SG)가 어떤 포트로 들어올 수 있나" 를 정한다.
# 출처를 IP 대역 대신 다른 SG 로 적으면 "그 SG 가 붙은 서버에서 오는 통신만" 허용된다.

# ALB: 사용자(CloudFront 경유) HTTPS 를 받는 유일한 입구.
resource "aws_security_group" "alb" {
  name        = "${var.project}-alb-sg"
  description = "Public entry: HTTPS from users"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from users"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-alb-sg"
  }
}

# Bastion: 관리자가 비공개 서버에 들어가기 전에 거치는 점프 서버.
resource "aws_security_group" "bastion" {
  name        = "${var.project}-bastion-sg"
  description = "Bastion host: SSH for administrators"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH for administrators"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-bastion-sg"
  }
}

# 웹 서버: ALB 가 보내는 HTTP 와 Bastion 에서 오는 SSH 만 받는다.
resource "aws_security_group" "web" {
  name        = "${var.project}-web-sg"
  description = "Web tier: HTTP from the ALB, SSH from the bastion"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTP from the ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "SSH from the bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-web-sg"
  }
}

# NLB: 웹 서버가 API 를 부르는 내부 로드밸런서.
resource "aws_security_group" "nlb" {
  name        = "${var.project}-nlb-sg"
  description = "Internal NLB: API calls from the web tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "API calls from the web tier"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-nlb-sg"
  }
}

# API 서버: NLB 를 거친 API 호출과 Bastion SSH 만 받는다.
resource "aws_security_group" "api" {
  name        = "${var.project}-api-sg"
  description = "API tier: calls through the NLB, SSH from the bastion"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "API calls through the NLB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.nlb.id]
  }

  ingress {
    description     = "SSH from the bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-api-sg"
  }
}

# Redis: API 서버의 캐시.
resource "aws_security_group" "redis" {
  name        = "${var.project}-redis-sg"
  description = "Cache: Redis from the API tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from the API tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-redis-sg"
  }
}

# MySQL (주·복제): 데이터 저장소.
resource "aws_security_group" "db" {
  name        = "${var.project}-db-sg"
  description = "Database: MySQL"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from the API tier"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }

  ingress {
    description     = "MySQL from the web tier"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-db-sg"
  }
}
