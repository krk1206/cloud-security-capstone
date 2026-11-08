# 입구 층: Route53(도메인) · ACM 인증서 · CloudFront(전 세계 캐시) · WAF(웹 방화벽).
# CloudFront → ALB 는 HTTPS 로만 붙는다. ALB 인증서는 origin.<도메인> 이름으로 발급하고 Route53 에서 DNS 로 검증한다.
# WAF 는 ALB 에 붙인다(리전 WAF). CloudFront 에 붙이는 WAF·사용자 도메인 인증서는 us-east-1 전용이라 이 시연 구성에서 뺐다.

resource "aws_route53_zone" "main" {
  name = var.domain_name
}

resource "aws_acm_certificate" "origin" {
  domain_name       = "origin.${var.domain_name}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "origin_validation" {
  zone_id         = aws_route53_zone.main.zone_id
  name            = tolist(aws_acm_certificate.origin.domain_validation_options)[0].resource_record_name
  type            = tolist(aws_acm_certificate.origin.domain_validation_options)[0].resource_record_type
  records         = [tolist(aws_acm_certificate.origin.domain_validation_options)[0].resource_record_value]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "origin" {
  certificate_arn         = aws_acm_certificate.origin.arn
  validation_record_fqdns = [aws_route53_record.origin_validation.fqdn]
}

resource "aws_route53_record" "origin" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "origin.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_cloudfront_distribution" "main" {
  enabled = true
  comment = "${var.project} edge"

  origin {
    origin_id   = "alb"
    domain_name = "origin.${var.domain_name}"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    # AWS 관리형 캐시 정책 'CachingDisabled' (동적 웹 서비스라 CloudFront 에서 캐시하지 않는다)
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_wafv2_web_acl" "alb" {
  name  = "${var.project}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common-rules"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common-rules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}
