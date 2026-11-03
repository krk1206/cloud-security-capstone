# 측정 지점 2대 — 설계도의 계층이 아니라 '바깥에서 들어오는 통신' 을 실제로 시험하기 위한 서버. security_groups.tf 와 무관한 자기 보안 그룹을 쓴다.
#
#   admin_vantage : 관리자 허용 목록 대역 안 (VPC 보조 CIDR, network.tf). Bastion 22 는 열려야 하고, 웹·API 22 직접은 막혀야 한다.
#   outsider      : 시험 VPC 의 공개 서브넷, 공인 IP. 허용 목록 밖의 인터넷 사용자. ALB 443 은 열려야 하고 Bastion 22 는 막혀야 한다.
#                   Bastion·ALB 의 '공인' 주소로만 연결한다. 상대 보안 그룹이 보는 출발 주소가 이 서버의 공인 IP 인지 사설 IP 인지는
#                   AWS 문서 문장으로 확인 못 함 — 어느 쪽이든 관리자 허용 목록 밖이라 이 시험의 기대값(막혀야 함)은 같다.
#                   처음에는 별도 VPC 에 두었으나 계정의 인터넷 게이트웨이 한도(리전당 기본 5개)에 걸려 옮겼다.
# 두 서버는 들어오는 규칙이 없다 (측정 결과는 직렬 콘솔로만 내보낸다).

resource "aws_security_group" "admin_vantage" {
  name        = "${var.project}-admin-vantage-sg"
  description = "Test vantage inside the admin allowlist range (no inbound)"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-admin-vantage-sg"
  }
}

resource "aws_instance" "admin_vantage" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.admin.id
  private_ip                  = local.ip.admin
  vpc_security_group_ids      = [aws_security_group.admin_vantage.id]
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "admin-vantage"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 0
    listen_port = 0
    probe       = true
    probe_cfg = jsonencode({
      from = "admin", interval = 15, console = true,
      targets = [
        { to = "bastion", host = local.ip.bastion, port = 22 },
        { to = "web", host = local.ip.web, port = 22 },
        { to = "api", host = local.ip.api, port = 22 },
        { to = "db", host = local.ip.db, port = 3306 },
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
    Name = "${var.project}-admin-vantage"
    Tier = "test-vantage"
  }
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}

# ----------------------------------------------------------------------------- 허용 목록 밖 인터넷 지점 (공개 서브넷, 공인 IP)
resource "aws_security_group" "outsider_vantage" {
  name        = "${var.project}-outsider-vantage-sg"
  description = "Internet test vantage outside the admin allowlist (no inbound)"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-outsider-vantage-sg"
  }
}

resource "aws_instance" "outsider" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public[1].id
  vpc_security_group_ids      = [aws_security_group.outsider_vantage.id]
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tftpl", {
    role        = "outsider"
    probe_py    = local.probe_py
    listen_py   = local.listen_py
    http_port   = 0
    listen_port = 0
    probe       = true
    probe_cfg = jsonencode({
      from = "outsider", interval = 15, console = true,
      targets = [
        { to = "bastion", host = aws_instance.bastion.public_ip, port = 22 },
        { to = "alb", host = aws_lb.alb.dns_name, port = 443 },
      ]
      fetch = [{ name = "web-via-alb", url = "http://${aws_lb.alb.dns_name}:443/" }]
    })
  })

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-outsider"
    Tier = "test-vantage"
  }

  depends_on = [aws_route_table_association.public]
  # 서버 이미지(AMI)는 처음 만들 때의 것을 그대로 쓴다. most_recent AMI 가 측정 도중에 새로 나와도 서버를 교체하지 않게 —
  # plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25)
  lifecycle {
    ignore_changes = [ami]
  }
}
