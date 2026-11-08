# 주문 리포트 버킷.
resource "aws_s3_bucket" "reports" {
  bucket = "${var.project}-reports-example"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
