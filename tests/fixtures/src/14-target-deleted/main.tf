provider "aws" {
  region = "ap-northeast-2"
}

# 대상 SG 를 삭제해서 finding 만 없앤 경우 (리소스 자체가 없다)
resource "aws_security_group" "other" {
  name        = "other-sg"
  description = "unrelated"
}
