output "role_name" {
  value = aws_iam_role.web.name
}

output "bucket_arn" {
  description = "패치가 Resource로 써야 하는 ARN"
  value       = aws_s3_bucket.assets.arn
}
