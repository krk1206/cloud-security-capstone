output "deploy_role_arn" {
  value       = aws_iam_role.deploy.arn
  description = "GitHub Variables 의 AWS_ROLE_DEPLOY 에 넣는다"
}

output "tfstate_bucket" {
  value       = aws_s3_bucket.tfstate.id
  description = "GitHub Variables 의 TFSTATE_BUCKET 에 넣는다"
}

output "oidc_sub" {
  value       = local.oidc_sub
  description = "이 역할을 받을 수 있는 GitHub 잡 (저장소 + Environment)"
}
