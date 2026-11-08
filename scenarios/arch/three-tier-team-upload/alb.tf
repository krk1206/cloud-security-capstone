# alb.tf - 인터넷에서 들어오는 HTTP를 받아 WEB ASG 인스턴스로 나눠 주는 Application Load Balancer.
# public 서브넷 2개(AZ-a, AZ-c)에 걸쳐 있어 한 AZ가 죽어도 받는다.

# Trivy AWS-0053(HIGH): "ALB가 인터넷에 공개됨". 사용자 트래픽을 받는 ALB는 공개가 설계 목적이다.
# 접근 제어는 ALB SG(80만), 그 뒤 WEB SG(ALB에서만)로 한다. 다음 단계: WAF 연결.
#trivy:ignore:AWS-0053
resource "aws_lb" "web" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id # [*] : count로 만든 2개 서브넷의 id 전부

  drop_invalid_header_fields = true # Trivy AWS-0052: 잘못된 HTTP 헤더 차단

  tags = { Name = "${var.project}-alb" }
}

# 타깃 그룹: ALB가 트래픽을 보낼 대상 집합. ASG가 인스턴스를 여기에 자동 등록한다.
resource "aws_lb_target_group" "web" {
  name     = "${var.project}-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = { Name = "${var.project}-web-tg" }
}

# Trivy AWS-0054(CRITICAL): "HTTP 리스너 사용". HTTPS에는 도메인 + ACM 인증서가 필요하다.
# 이번 주 범위에는 도메인(Route 53)이 없어 HTTP로 두고, 다음 단계에서 ACM 인증서 + 443 리스너 + 80->443 리다이렉트로 바꾼다.
#trivy:ignore:AWS-0054
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
