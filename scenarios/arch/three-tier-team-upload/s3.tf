# s3.tf - 정적 파일/백업용 버킷. 퍼블릭 접근 4종 차단, ACL 비활성화, 버전 관리, 서버 측 암호화.
# 우리 연구의 시나리오 2(Public S3)는 이 설정이 빠지거나 풀린 상태를 뜻한다.

resource "aws_s3_bucket" "assets" {
  bucket_prefix = "${var.project}-assets-" # 버킷 이름은 전 세계 유일. 접두어 뒤에 AWS가 난수를 붙인다.
  force_destroy = true                     # 실습용: 객체가 있어도 destroy 가능

  tags = { Name = "${var.project}-assets" }
}

# 계정 수준 차단과 별개로 버킷 수준에서 퍼블릭 ACL/정책을 전부 막는다(Trivy AWS-0086/0087/0091/0093).
resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACL 자체를 끈다. 접근 제어는 IAM/버킷 정책으로만 한다.
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

# Trivy AWS-0088(HIGH)은 암호화 설정 유무, AWS-0132(HIGH)는 고객 관리형 KMS 키 사용 여부를 본다.
# SSE-S3(AES256)로 암호화하고, KMS 키는 키 요금과 삭제 대기 기간(7~30일) 때문에 샌드박스 범위 밖으로 둔다.
#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
