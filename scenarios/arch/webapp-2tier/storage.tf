# 저장 층: 웹 서버가 쓰는 정적 자산(이미지·CSS) 버킷. 웹 서버는 IAM 역할(iam.tf)로 이 버킷에 접근한다.

# 버킷 본체. force_destroy = true: 안에 객체가 있어도 terraform destroy 가 지울 수 있게 (시연 뒤 정리용).
resource "aws_s3_bucket" "assets" {
  bucket        = var.bucket_name
  force_destroy = true

  tags = {
    Name = "${var.project}-assets"
  }
}

# 퍼블릭 액세스 차단 설정. AWS 는 새 버킷에 네 항목을 모두 true(차단)로 두는데, 여기서는 전부 false 로 푼다.
resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 버킷 정책: 누구나(Principal "*") 객체를 읽을(s3:GetObject) 수 있게 한다.
# depends_on: 퍼블릭 정책은 위 차단 설정이 먼저 풀려야 적용되므로 순서를 명시한다.
resource "aws_s3_bucket_policy" "assets_public_read" {
  bucket = aws_s3_bucket.assets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.assets.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.assets]
}
