# iam.tf - WEB 인스턴스가 쓰는 IAM 역할.

# 신뢰 정책: 누가 이 역할을 쓸 수 있나 -> EC2 서비스
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "web" {
  name               = "${var.project}-web-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Name = "${var.project}-web-role" }
}

# 권한 정책: 무엇을 할 수 있나
data "aws_iam_policy_document" "web_s3_read" {
  statement {
    sid       = "ReadAssetsObjects"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }

  statement {
    sid       = "ListAssetsBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.assets.arn]
  }

  statement {
    sid       = "UploadAssets"
    actions   = ["s3:Put*"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }
}

resource "aws_iam_role_policy" "web_s3_read" {
  name   = "${var.project}-web-s3-read"
  role   = aws_iam_role.web.id
  policy = data.aws_iam_policy_document.web_s3_read.json
}

# SSM Session Manager로 포트 개방 없이 접속하기 위한 AWS 관리형 정책
resource "aws_iam_role_policy_attachment" "web_ssm" {
  role       = aws_iam_role.web.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# 인스턴스 프로파일: 역할을 EC2에 붙이는 포장. 시작 템플릿이 이 이름을 참조한다.
resource "aws_iam_instance_profile" "web" {
  name = "${var.project}-web-profile"
  role = aws_iam_role.web.name
}
