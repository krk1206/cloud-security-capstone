# 주문 데이터베이스 (PostgreSQL). 비밀번호는 코드에 적지 않고 AWS 가 Secrets Manager 로 관리.
resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "orders" {
  identifier                  = "${var.project}-db"
  engine                      = "postgres"
  engine_version              = "16.4"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  storage_encrypted           = true
  username                    = "orders"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.main.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  backup_retention_period     = 7
  skip_final_snapshot         = true
}
