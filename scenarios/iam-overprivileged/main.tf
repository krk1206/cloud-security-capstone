# 시나리오 3: IAM 과다 권한 (의도적 misconfiguration)
# 정상 기준은 infrastructure/three-tier/iam.tf 다. 거기서는 WEB 역할이 assets 버킷의 GetObject/ListBucket만 갖는다.
# 여기서는 같은 구조에서 권한 정책만 "Action: *, Resource: *"로 망가뜨렸다.
# 기대 패치(policy/patch-whitelist.md 6절): actions/resources를 policy/required_permissions.yaml 의 목록으로 교체.
# 정상 기능(V8): 패치 뒤에도 역할로 버킷 객체 읽기가 성공해야 한다.

# ---- 정상 리소스: 역할이 접근해야 하는 버킷 (안전 설정, 시나리오 대상 아님) ----
resource "aws_s3_bucket" "assets" {
  bucket_prefix = "${var.project}-assets-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id

  versioning_configuration {
    status = "Enabled"
  }
}

#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---- 정상 리소스: 신뢰 정책 (EC2가 이 역할을 쓸 수 있음) ----
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
}

# ---- 결함 지점: 권한 정책이 모든 행동을 모든 리소스에 허용 ----
# 정상이라면:
#   actions = ["s3:GetObject"],  resources = ["${aws_s3_bucket.assets.arn}/*"]
#   actions = ["s3:ListBucket"], resources = [aws_s3_bucket.assets.arn]
data "aws_iam_policy_document" "web_overprivileged" {
  statement {
    sid       = "AllowEverything"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "web" {
  name   = "${var.project}-web-policy"
  role   = aws_iam_role.web.id
  policy = data.aws_iam_policy_document.web_overprivileged.json
}

resource "aws_iam_instance_profile" "web" {
  name = "${var.project}-web-profile"
  role = aws_iam_role.web.name
}
