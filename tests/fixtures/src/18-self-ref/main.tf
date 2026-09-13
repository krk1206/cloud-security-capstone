provider "aws" {
  region = "ap-northeast-2"
}

# self = true: 같은 SG 가 붙은 ENI 끼리 허용. 승인 목록에 "self" 가 없으면 EXCESS
resource "aws_security_group" "cluster" {
  name        = "cluster-sg"
  description = "intra-cluster ssh"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    self      = true
  }
}
