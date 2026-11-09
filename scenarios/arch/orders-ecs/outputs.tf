output "alb_dns_name" {
  description = "주문 API 공개 주소."
  value       = aws_lb.public.dns_name
}
