# 운영 서버: 관리자가 SSH 로 들어와 DB 를 점검한다 (공개 서브넷).
resource "aws_instance" "ops" {
  ami                    = var.ops_ami_id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.ops.id]

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-ops"
  }
}
