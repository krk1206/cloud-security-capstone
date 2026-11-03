# 로드밸런서 층: 공개 ALB(사용자 → 웹 서버)와 내부 NLB(웹 서버 → API 서버).

resource "aws_lb" "alb" {
  name                       = "${var.project}-alb"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "web" {
  name        = "${var.project}-web-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path    = "/"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.origin.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_lb" "nlb" {
  name               = "${var.project}-nlb"
  load_balancer_type = "network"
  internal           = true
  security_groups    = [aws_security_group.nlb.id]
  subnets            = aws_subnet.private[*].id
}

resource "aws_lb_target_group" "api" {
  name        = "${var.project}-api-tg"
  port        = 8080
  protocol    = "TCP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 8080
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
