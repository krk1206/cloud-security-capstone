# 데이터 층: MySQL 주(가용 영역 1) + 읽기 복제(가용 영역 2), Redis 캐시(두 노드, 자동 장애 조치). 전부 비공개 서브넷.

resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db-subnets"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "primary" {
  identifier                          = "${var.project}-mysql"
  engine                              = "mysql"
  engine_version                      = "8.0"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  db_name                             = var.db_name
  username                            = "appadmin"
  manage_master_user_password         = true
  db_subnet_group_name                = aws_db_subnet_group.main.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  availability_zone                   = var.azs[0]
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  backup_retention_period             = 7
  publicly_accessible                 = false
  skip_final_snapshot                 = true
}

resource "aws_db_instance" "replica" {
  identifier             = "${var.project}-mysql-replica"
  replicate_source_db    = aws_db_instance.primary.identifier
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
  availability_zone      = var.azs[1]
  publicly_accessible    = false
  skip_final_snapshot    = true
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project}-cache-subnets"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.project}-redis"
  description                = "API cache"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 2
  port                       = 6379
  automatic_failover_enabled = true
  multi_az_enabled           = true
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  snapshot_retention_limit   = 1
}
