# 프로그램(2차 검사)이 terraform show -json 으로 읽는 값
output "alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "nlb_dns_name" {
  value = aws_lb.nlb.dns_name
}

output "bastion_public_ip" {
  value = aws_instance.bastion.public_ip
}

output "outsider_public_ip" {
  value = aws_instance.outsider.public_ip
}

output "private_ips" {
  value = local.ip
}

output "vantage_instance_ids" {
  description = "측정 결과를 콘솔 출력으로 읽어 올 서버 (get-console-output --latest)"
  value = {
    web      = aws_instance.web.id
    api      = aws_instance.api.id
    bastion  = aws_instance.bastion.id
    admin    = aws_instance.admin_vantage.id
    outsider = aws_instance.outsider.id
  }
}
