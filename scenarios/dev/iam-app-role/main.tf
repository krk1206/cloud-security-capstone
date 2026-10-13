provider "aws" {
  region = "ap-northeast-2"
}

# 앱 서버(EC2)가 맡는 역할. 앱은 자기 데이터 버킷(app-data)에서 객체를 읽고 목록만 보면 된다.
resource "aws_iam_role" "app" {
  name = "app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# 잘못된 설정: 필요한 건 s3:GetObject / s3:ListBucket (app-data 버킷) 인데 S3 전체 권한을 모든 리소스에 준다.
resource "aws_iam_policy" "app" {
  name        = "app-policy"
  description = "App server access to its data bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AppAccess"
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app.arn
}
