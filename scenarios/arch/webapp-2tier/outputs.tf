# 출력값: apply 가 끝난 뒤 화면에 보여 주는 값. 시연 때 이 값으로 브라우저 접속·콘솔 확인을 한다.

output "web_public_ip" {
  description = "웹 서버 퍼블릭 IP. 브라우저에서 http://<이 값>/ 로 접속하면 nginx 페이지가 떠야 한다 (정상 기능 확인)."
  value       = aws_instance.web.public_ip
}

output "web_url" {
  description = "웹 서버 접속 주소."
  value       = "http://${aws_instance.web.public_ip}/"
}

output "app_private_ip" {
  description = "앱 서버 사설 IP (인터넷에서는 접근 불가)."
  value       = aws_instance.app.private_ip
}

output "web_security_group_id" {
  description = "웹 SG ID. 배포 후 검증(V7)은 이 SG 의 실제 규칙을 describe-security-groups 로 읽는다."
  value       = aws_security_group.web.id
}

output "assets_bucket" {
  description = "정적 자산 버킷 이름."
  value       = aws_s3_bucket.assets.bucket
}

output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.main.id
}
