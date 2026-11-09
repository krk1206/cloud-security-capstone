# monitoring.tf - CloudWatch. 교수님 그림의 CloudWatch 요소. 이번 주는 최소 구성:
# 1) 타깃 그룹의 비정상 인스턴스 수 경보(ALB 헬스체크 실패 감지), 2) 웹 로그 그룹(에이전트 연동은 다음 단계)

resource "aws_cloudwatch_metric_alarm" "web_unhealthy_hosts" {
  alarm_name          = "${var.project}-web-unhealthy-hosts"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.web.arn_suffix
    TargetGroup  = aws_lb_target_group.web.arn_suffix
  }

  alarm_description = "WEB 타깃 그룹에 비정상 인스턴스가 1개 이상"
}

resource "aws_cloudwatch_log_group" "web" {
  name              = "/${var.project}/web"
  retention_in_days = 7
}
