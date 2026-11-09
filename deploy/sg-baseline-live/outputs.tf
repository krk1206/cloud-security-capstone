output "sg_id" {
  value       = module.sg.sg_id
  description = "반영 대상 SG (intent 의 aws_security_group.vulnerable_ssh) — V7 --sg-ids 에 넘긴다"
}

output "target_public_ip" {
  value       = aws_instance.target.public_ip
  description = "V8 과녁 EC2 의 공인 IP"
}

output "vpc_id" {
  value       = aws_vpc.live.id
  description = "상시 환경 VPC"
}
