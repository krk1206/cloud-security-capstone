# 권한 층: 웹 서버(EC2)가 S3 버킷에 접근할 때 쓰는 IAM 역할. 액세스 키를 서버에 넣는 대신 역할을 "입혀서" 권한을 준다.

# 역할. assume_role_policy(신뢰 정책) = "누가 이 역할을 맡을 수 있나" → EC2 서비스만.
resource "aws_iam_role" "web" {
  name = "${var.project}-web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# 권한 정책 = "이 역할이 무엇을 할 수 있나". 웹 서버가 필요한 것은 assets 버킷의 객체 읽기와 목록 조회다.
resource "aws_iam_policy" "web_assets" {
  name        = "${var.project}-web-assets-policy"
  description = "Web tier access to the static assets bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssetsAccess"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}/*"]
    }]
  })
}

# 정책을 역할에 붙인다.
resource "aws_iam_role_policy_attachment" "web_assets" {
  role       = aws_iam_role.web.name
  policy_arn = aws_iam_policy.web_assets.arn
}

# 인스턴스 프로필: EC2 에 역할을 붙일 때 쓰는 포장. compute.tf 의 aws_instance.web 이 이것을 참조한다.
resource "aws_iam_instance_profile" "web" {
  name = "${var.project}-web-profile"
  role = aws_iam_role.web.name
}
