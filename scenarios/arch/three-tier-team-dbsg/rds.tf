# rds.tf - DB 계층. RDS MySQL 8.0, db 서브넷(private) 2개 위, 외부 비공개, 저장소 암호화.
# DB 선택 근거: 관리형(패치/백업/장애조치 자동), MySQL 호환, Read Replica로 "Master/Slave" 확장 가능.
# 교수님 그림의 Master/Slave = Primary + Read Replica. 비용 때문에 이번 주는 Primary 1개(단일 AZ).
# Multi-AZ(장애조치용 대기 복제본, 읽기 불가)와 Read Replica(읽기 분산, 비동기 복제)는 다른 기능이다.

# 서브넷 그룹: RDS가 어느 서브넷에 ENI를 놓을지. 서로 다른 AZ의 서브넷이 2개 이상 필요하다.
resource "aws_db_subnet_group" "db" {
  name       = "${var.project}-db-subnets"
  subnet_ids = aws_subnet.db[*].id
  tags       = { Name = "${var.project}-db-subnets" }
}

resource "aws_db_instance" "mysql" {
  identifier     = "${var.project}-mysql"
  engine         = "mysql"
  engine_version = "8.0" # 접두어 지정: auto_minor_version_upgrade(기본 true)와 함께 최신 8.0.x 사용
  instance_class = var.db_instance_class

  allocated_storage = 20 # gp3 최소 20GiB
  storage_type      = "gp3"
  storage_encrypted = true # Trivy AWS-0080

  db_name  = "appdb"
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false # Trivy AWS-0180. db 서브넷에는 IGW 경로도 없다.
  multi_az               = false # 비용. 운영이면 true

  backup_retention_period             = 7    # Trivy AWS-0077(MEDIUM): 2일 미만이면 finding. 자동 백업 7일 보관
  iam_database_authentication_enabled = true # Trivy AWS-0176(MEDIUM)

  # 실습용: destroy가 막히지 않게 둔다. 운영이면 deletion_protection = true, skip_final_snapshot = false
  deletion_protection = false
  skip_final_snapshot = true
  apply_immediately   = true

  tags = { Name = "${var.project}-mysql", Tier = "db" }
}
