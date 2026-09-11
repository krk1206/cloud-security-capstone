output "sg_id" {
  value       = aws_security_group.vulnerable_ssh.id
  description = "V7 실측에서 describe-security-groups 에 사용"
}
