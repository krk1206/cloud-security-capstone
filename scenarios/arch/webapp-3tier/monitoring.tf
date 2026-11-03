# 모니터링: 애플리케이션 로그 보관과 경보 두 개 (ALB 5xx 급증, DB CPU 과다).

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = 30
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.project}-alb-5xx"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"

  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "${var.project}-db-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.primary.identifier
  }
}
