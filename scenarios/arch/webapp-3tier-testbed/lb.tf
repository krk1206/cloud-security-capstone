# 로드밸런서 2개 — 원본 설계와 같은 자리, 같은 보안 그룹.
#   ALB (인터넷 쪽, 공개 서브넷): 443 → 웹 80. 원본은 HTTPS(인증서) — 여기서는 인증서 없이 443 포트에 HTTP 로 연다 (보안 그룹 규칙은 같다).
#   NLB (내부, 비공개 서브넷 1곳): 8080 → API 8080. preserve_client_ip = false — API 가 보는 출발지가 NLB(보안 그룹 nlb)가 되게.
#     원본은 비공개 서브넷 2곳에 걸쳐 있다. 시험 환경은 API 서버가 1대(가용 영역 a)라서 NLB 도 같은 영역 1곳에만 둔다
#     (NLB 는 대상이 없는 영역의 주소를 DNS 에서 뺀다 — ELB 문서 'Health checks for Network Load Balancer target groups').

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

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}

resource "aws_lb_listener" "alb_443" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTP"

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
  subnets            = [aws_subnet.private[0].id]
}

resource "aws_lb_target_group" "api" {
  name               = "${var.project}-api-tg"
  port               = 8080
  protocol           = "TCP"
  vpc_id             = aws_vpc.main.id
  target_type        = "instance"
  preserve_client_ip = "false"
}

resource "aws_lb_target_group_attachment" "api" {
  target_group_arn = aws_lb_target_group.api.arn
  target_id        = aws_instance.api.id
  port             = 8080
}

resource "aws_lb_listener" "nlb_8080" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 8080
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
