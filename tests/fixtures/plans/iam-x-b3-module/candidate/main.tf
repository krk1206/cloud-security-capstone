provider "aws" {
  region = "ap-northeast-2"
}

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

resource "aws_iam_policy" "worker" {
  name        = "report-worker-policy"
  description = "Report worker access to the report archive bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReportArchiveAccess"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::report-archive", "arn:aws:s3:::report-archive/*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker" {
  role       = aws_iam_role.worker.name
  policy_arn = aws_iam_policy.worker.arn
}

module "ops" {
  source    = "./ops"
  role_name = aws_iam_role.worker.name
}
