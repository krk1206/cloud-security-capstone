provider "aws" {
  region = "ap-northeast-2"
}

# 리포트 생성 워커(EC2)가 맡는 역할. 워커는 report-archive 버킷의 객체를 읽고 목록만 보면 된다.
resource "aws_iam_role" "worker" {
  name = "report-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# 잘못된 설정: 필요한 건 s3:GetObject / s3:ListBucket (report-archive) 인데 S3 전체 권한을 모든 리소스에 준다.
resource "aws_iam_policy" "worker" {
  name        = "report-worker-policy"
  description = "Report worker access to the report archive bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReportArchiveAccess"
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "*"
      Condition = { IpAddress = { "aws:SourceIp" = "10.0.0.0/8" } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker" {
  role       = aws_iam_role.worker.name
  policy_arn = aws_iam_policy.worker.arn
}
