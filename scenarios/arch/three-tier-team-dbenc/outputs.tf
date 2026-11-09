# outputs.tf - apply 후 확인에 필요한 값
output "alb_dns_name" {
  description = "브라우저/curl로 접속: http://<이 값>"
  value       = aws_lb.web.dns_name
}

output "bastion_public_ip" {
  description = "ssh -i ~/.ssh/capstone ec2-user@<이 값>"
  value       = aws_instance.bastion.public_ip
}

output "rds_endpoint" {
  description = "Bastion에서: mysql -h <이 값의 호스트 부분> -u admin -p"
  value       = aws_db_instance.mysql.address
}

output "s3_bucket_name" {
  value = aws_s3_bucket.assets.id
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "nat_public_ip" {
  description = "private 인스턴스의 아웃바운드가 나가는 공인 IP"
  value       = aws_eip.nat.public_ip
}
