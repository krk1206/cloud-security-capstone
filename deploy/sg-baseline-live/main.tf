# sg-baseline 상시 환경 (워크플로 ③ iacpatch-deploy 전용)
#
# 목적: main 에 병합된 sg-baseline 을 "계속 켜져 있는 환경" 에 사람 승인 뒤 반영하고, 반영 전후 V7 · V8 을 잰다.
# - 임시 시험 환경(infrastructure/sg-baseline-testbed, 워크플로 ②)과 같은 모양이지만 지우지 않는다.
# - 상태(state)는 S3 에 둔다 (backend.tf). 실행마다 이어서 쓰기 때문이다. 임시 환경은 한 실행 안에서 지워서 상태가 필요 없다.
# - sg-baseline 폴더는 건드리지 않고 module 로 끌어다 쓴다 (main 의 sg-baseline 이 그대로 들어온다).
# - EC2 1대가 V8 의 과녁이다: 80 열려야 함(정상 기능), 22 · 3389 는 인터넷(러너)에서 막혀야 함.
# - 패키지를 설치하지 않는다 (AL2023 에 들어 있는 python3 로 80 을 연다) → 바깥으로 나가는 통신이 필요 없다.
# - 이 폴더는 infrastructure/ 밖에 둔다. 스캔 대상(고칠 코드)이 아니라 배포 설정이기 때문이다.
#
# 비용: VPC · IGW · 서브넷 무료, t3.micro 1대가 계속 켜져 있다. 안 쓸 때는 워크플로 ③ 을 action=destroy 로 돌린다.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "capstone-2026"
      ManagedBy = "terraform"
      Purpose   = "iacpatch-live"
      iacpatch  = "live"
    }
  }
}

locals {
  prefix = "capstone-live"
}

# ---------------------------------------------------------------------------
# 상시 네트워크: VPC + public 서브넷 1개 + IGW + 라우트 (NAT 없음)
# 서브넷에 공인 IP 자동 할당을 켜지 않는다. 공인 IP 는 과녁 EC2 하나에만 직접 붙인다.
# ---------------------------------------------------------------------------
resource "aws_vpc" "live" {
  cidr_block           = "10.78.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "live" {
  vpc_id = aws_vpc.live.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.live.id
  cidr_block = "10.78.1.0/24"
  tags       = { Name = "${local.prefix}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.live.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.live.id
  }
  tags = { Name = "${local.prefix}-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# 반영 대상: sg-baseline 그대로 (main 에 병합된 코드)
# ---------------------------------------------------------------------------
module "sg" {
  source = "../../infrastructure/sg-baseline"
  vpc_id = aws_vpc.live.id
  region = var.region
}

# 공개 웹 포트. 보호 대상(22/3389) 이 아니다. V8 "허용 통신 성공" 의 과녁.
# egress 블록이 없다 = 바깥으로 나가는 통신 없음 (패키지 설치를 안 하므로 필요 없다).
resource "aws_security_group" "web" {
  name        = "${local.prefix}-web"
  description = "live: public HTTP so V8 can prove the instance is reachable"
  vpc_id      = aws_vpc.live.id

  ingress {
    description = "HTTP from anywhere (public web, intentionally open)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-web" }
}

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

resource "aws_instance" "target" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [module.sg.sg_id, aws_security_group.web.id]

  # AMI 가 새로 나와도 이 EC2 를 다시 만들지 않는다 (상시 환경이 패치와 상관없이 교체되면 안 된다)
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted = true
  }

  # 패키지 설치 없이 80 을 연다 (AL2023 기본 python3)
  user_data = <<-EOF
    #!/bin/bash
    mkdir -p /srv/www
    echo "<h1>iacpatch live</h1>" > /srv/www/index.html
    cat > /etc/systemd/system/iacpatch-web.service <<'UNIT'
    [Unit]
    Description=iacpatch live web (V8 target)
    After=network-online.target
    [Service]
    ExecStart=/usr/bin/python3 -m http.server 80 --directory /srv/www
    Restart=always
    [Install]
    WantedBy=multi-user.target
    UNIT
    systemctl daemon-reload
    systemctl enable --now iacpatch-web.service
  EOF

  tags = { Name = "${local.prefix}-target" }
}
