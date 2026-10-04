# 보안 그룹(SG) 층: 인스턴스 단위 방화벽. "어떤 출처(IP 대역 또는 다른 SG)가 어떤 포트로 들어올 수 있나" 를 정한다.
# ingress = 들어오는 트래픽, egress = 나가는 트래픽. 적지 않은 것은 전부 막힌다.

# 웹 서버 SG: 인터넷 전체(0.0.0.0/0)에서 HTTP(80) 로 들어오는 것이 이 서버의 존재 이유다.
resource "aws_security_group" "web" {
  name        = "${var.project}-web-sg"
  description = "Web tier: HTTP from the internet, SSH for administration"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from anywhere (public web server)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH for administration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "All outbound (package install, S3 access)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-web-sg"
  }
}

# 앱 서버 SG: 출처를 IP 대역이 아니라 "웹 서버 SG" 로 적는다. 웹 서버 SG 가 붙은 인스턴스만 8080 으로 들어올 수 있다.
resource "aws_security_group" "app" {
  name        = "${var.project}-app-sg"
  description = "App tier: only the web tier may call the app port"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "App port from the web tier only"
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
    Name = "${var.project}-app-sg"
  }
}
