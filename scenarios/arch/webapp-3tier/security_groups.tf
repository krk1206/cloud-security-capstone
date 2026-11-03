# ALB Security Group
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

# Bastion Security Group
resource "aws_security_group" "bastion" {
  name        = "${var.project}-bastion-sg"
  description = "Bastion host: SSH for administrators"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH for administrators"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"

    # 수정 1: 관리자 대역만 허용
    cidr_blocks = [
      "203.0.113.0/24",
      "198.51.100.0/24"
    ]
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

# Web Security Group
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

# NLB Security Group
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

# API Security Group
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

# Redis Security Group
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

# MySQL Security Group
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

  # 수정 2:
  # WEB -> MySQL 3306 허용 ingress 블록 삭제
  # API -> MySQL 3306 허용 규칙만 유지

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