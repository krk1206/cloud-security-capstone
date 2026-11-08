# 서버 5대 (모두 t3.micro, Amazon Linux 2023). 보안 그룹은 security_groups.tf 그대로 붙인다.
#   bastion : 공개 서브넷, 공인 IP. sshd(22) 그대로. 측정기 → 웹·API 22, MySQL 3306, Redis 6379, NLB 8080, 웹 80, API 8080
#   web     : 비공개. HTTP 80 (/probe.json) + 측정기 → NLB 8080, API 8080(직접), MySQL, Redis, Bastion 22 + (NLB 경유) API 결과 받기
#   api     : 비공개. HTTP 8080 (/probe.json) + 측정기 → MySQL, Redis, Bastion 22, 웹 80, NLB 8080
#   db      : 비공개. 3306 대역(stand-in) — 실제 MySQL 아님
#   redis   : 비공개. 6379 대역(stand-in) — 실제 Redis 아님
# 측정 결과는 직렬 콘솔에도 찍힌다 → 프로그램이 `aws ec2 get-console-output --latest` 로 읽는다 (보안 그룹을 열지 않고 받는 길).
# 사설 IP 를 고정해 둔다: 서로의 주소를 측정 설정에 넣어도 Terraform 의존성이 꼬이지 않게.

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

locals {
  probe_py  = file("${path.module}/probe.py")
  listen_py = file("${path.module}/listen.py")

  ip = {
    bastion = cidrhost(cidrsubnet(var.vpc_cidr, 8, 1), 10)
    web     = cidrhost(cidrsubnet(var.vpc_cidr, 8, 11), 10)
    api     = cidrhost(cidrsubnet(var.vpc_cidr, 8, 11), 20)
    db      = cidrhost(cidrsubnet(var.vpc_cidr, 8, 12), 30)
    redis   = cidrhost(cidrsubnet(var.vpc_cidr, 8, 12), 40)
    admin   = cidrhost(cidrsubnet(var.admin_vantage_cidr, 2, 0), 10)
  }
}

resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public[0].id
  private_ip                  = local.ip.bastion
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "bastion"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 0
    listen_port = 0
    probe       = true
    probe_cfg = jsonencode({
      from = "bastion", interval = 15, console = true,
      targets = [
        { to = "web", host = local.ip.web, port = 22 },
        { to = "api", host = local.ip.api, port = 22 },
        { to = "db", host = local.ip.db, port = 3306 },
        { to = "redis", host = local.ip.redis, port = 6379 },
        { to = "nlb", host = aws_lb.nlb.dns_name, port = 8080 },
        { to = "web", host = local.ip.web, port = 80 },
        { to = "api", host = local.ip.api, port = 8080 },
      ]
    })
  })

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-bastion"
    Tier = "bastion"
  }
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_instance" "db" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[1].id
  private_ip                  = local.ip.db
  vpc_security_group_ids      = [aws_security_group.db.id]
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "mysql"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 0
    listen_port = 3306
    probe       = false
    probe_cfg   = "{}"
  })

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-db-standin"
    Tier = "db"
  }
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_instance" "redis" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[1].id
  private_ip                  = local.ip.redis
  vpc_security_group_ids      = [aws_security_group.redis.id]
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "redis"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 0
    listen_port = 6379
    probe       = false
    probe_cfg   = "{}"
  })

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-redis-standin"
    Tier = "redis"
  }
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_instance" "api" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[0].id
  private_ip                  = local.ip.api
  vpc_security_group_ids      = [aws_security_group.api.id]
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "api"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 8080
    listen_port = 0
    probe       = true
    probe_cfg = jsonencode({
      from = "api", interval = 15, console = true, out = "/srv/www/probe.json",
      targets = [
        { to = "db", host = local.ip.db, port = 3306 },
        { to = "redis", host = local.ip.redis, port = 6379 },
        { to = "bastion", host = local.ip.bastion, port = 22 },
        { to = "web", host = local.ip.web, port = 80 },
        { to = "nlb", host = aws_lb.nlb.dns_name, port = 8080 },
      ]
    })
  })

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-api"
    Tier = "api"
  }
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_instance" "web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[0].id
  private_ip                  = local.ip.web
  vpc_security_group_ids      = [aws_security_group.web.id]
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "web"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 80
    listen_port = 0
    probe       = true
    probe_cfg = jsonencode({
      from = "web", interval = 15, console = true, out = "/srv/www/probe.json",
      targets = [
        { to = "nlb", host = aws_lb.nlb.dns_name, port = 8080 },
        { to = "api", host = local.ip.api, port = 8080 },
        { to = "db", host = local.ip.db, port = 3306 },
        { to = "redis", host = local.ip.redis, port = 6379 },
        { to = "bastion", host = local.ip.bastion, port = 22 },
      ]
      fetch = [{ name = "api-via-nlb", url = "http://${aws_lb.nlb.dns_name}:8080/probe.json" }]
    })
  })

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-web"
    Tier = "web"
  }
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}
