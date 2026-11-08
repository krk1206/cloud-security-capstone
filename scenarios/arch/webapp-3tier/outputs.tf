output "cloudfront_domain" {
  description = "사용자 접속 주소 (CloudFront 기본 도메인)"
  value       = aws_cloudfront_distribution.main.domain_name
}

output "alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "nlb_dns_name" {
  value = aws_lb.nlb.dns_name
}

output "bastion_public_ips" {
  value = aws_instance.bastion[*].public_ip
}

output "db_endpoint" {
  value = aws_db_instance.primary.address
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}
