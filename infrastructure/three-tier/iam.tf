# iam.tf - WEB 인스턴스가 쓰는 IAM 역할. 최소 권한: 이 버킷 읽기 + SSM 접속만.
# 우리 연구의 시나리오 3(IAM 과다 권한)은 이 정책이 "Action": "*", "Resource": "*"인 상태를 뜻한다.

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

# 권한 정책: 무엇을 할 수 있나 -> assets 버킷 객체 읽기, 목록 조회. 리소스를 ARN으로 못 박는다.
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
