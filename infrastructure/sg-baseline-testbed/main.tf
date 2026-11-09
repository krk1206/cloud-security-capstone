# sg-baseline 임시 시험 환경 (워크플로 ② iacpatch-testbed 전용)
#
# 목적: 패치된 sg-baseline 을 "격리된 임시 VPC" 에 실제로 올려 V7(실제 AWS 설정) · V8(통신) 을 재고 바로 지운다.
# - sg-baseline 폴더는 건드리지 않고 module 로 끌어다 쓴다 (패치 PR 이 바꾼 main.tf 가 그대로 들어온다).
# - VPC 를 따로 만들어서 상시 환경(기본 VPC)·다른 실행과 이름이 겹치지 않게 한다. 전부 run_id 태그를 단다.
# - EC2 1대(t3.micro, Amazon Linux 2023, nginx) 가 V8 의 과녁이다:
#     80  : 공개 웹 → 러너에서 열려야 함 (정상 기능 보존)
#     22  : 승인 출처 10.0.0.0/8 만 → 러너(인터넷) 에서 막혀야 함
#     3389: 승인 출처 없음 → 러너에서 막혀야 함
# - 이 폴더는 CI 가 apply → 측정 → destroy 까지 한 실행 안에서 끝낸다. 사람이 로컬에서 쓸 일은 없다.
#
# 비용: VPC/IGW/서브넷 무료, t3.micro 몇 분. NAT 없음.

terraform {
  required_version = ">= 1.5"
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
      Project      = "capstone-2026"
      ManagedBy    = "terraform"
      Purpose      = "iacpatch-testbed"
      iacpatch-run = var.run_id
    }
  }
}

locals {
  prefix = "capstone-tmp-${var.run_id}"
}

# ---------------------------------------------------------------------------
# 격리 네트워크: VPC + public 서브넷 1개 + IGW + 라우트 (NAT 없음)
# ---------------------------------------------------------------------------
resource "aws_vpc" "tmp" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "tmp" {
  vpc_id = aws_vpc.tmp.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.tmp.id
  cidr_block              = "10.77.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.prefix}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.tmp.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.tmp.id
  }
  tags = { Name = "${local.prefix}-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# 검증 대상: sg-baseline 그대로 (패치 PR 의 main.tf 가 여기로 들어온다)
# ---------------------------------------------------------------------------
module "sg" {
  source = "../sg-baseline"
  vpc_id = aws_vpc.tmp.id
  region = var.region
}

# 공개 웹 포트. 보호 대상(22/3389) 이 아니라 V7 오라클이 보지 않는다. V8 "허용 통신 성공" 의 과녁.
resource "aws_security_group" "web" {
  name        = "${local.prefix}-web"
  description = "testbed: public HTTP so V8 can prove the instance is reachable"
  vpc_id      = aws_vpc.tmp.id

  ingress {
    description = "HTTP from anywhere (public web, intentionally open)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "outbound for package install"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-web" }
}

# AMI 는 ID 를 박지 않고 찾는다 (ec2:DescribeImages 만 있으면 됨 — plan 전용 역할로도 plan 이 된다)
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

  user_data = <<-EOF
    #!/bin/bash
    dnf install -y nginx
    echo "<h1>iacpatch testbed ${var.run_id}</h1>" > /usr/share/nginx/html/index.html
    systemctl enable --now nginx
  EOF

  tags = { Name = "${local.prefix}-target" }

  # 한 실행 안에서 "원본 apply → 패치 plan" 사이에 AL2023 최신 AMI 가 바뀌면 plan 이 이 서버를 '교체' 로 잡는다.
  # 이 서버는 V8 의 과녁일 뿐 패치 대상이 아니므로 AMI·user_data 변화로 다시 만들지 않는다.
  lifecycle {
    ignore_changes = [ami, user_data]
  }
}
