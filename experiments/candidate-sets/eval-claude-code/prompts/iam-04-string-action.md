다음 Terraform 파일에서 Trivy 가 아래 설정 오류를 보고했다. 파일을 고쳐서 전체 내용을 돌려줘.

- 파일: main.tf  (내용은 아래)
- 룰: AVD-AWS-0345 — Disallow unrestricted S3 IAM Policies
- 지목 리소스: aws_iam_policy.worker  (24 번째 줄)
- 이 역할/정책에 허용돼야 하는 권한: actions ['s3:GetObject', 's3:ListBucket'] on resources ['arn:aws:s3:::report-archive', 'arn:aws:s3:::report-archive/*']  (그 외 어떤 액션·리소스도 허용하면 안 된다)
- 다른 리소스나 파일은 만들지 말고, 이 파일의 수정본 전체만 코드 블록 하나로 출력해줘.

```hcl
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
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker" {
  role       = aws_iam_role.worker.name
  policy_arn = aws_iam_policy.worker.arn
}
```
