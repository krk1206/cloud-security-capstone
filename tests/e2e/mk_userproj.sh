#!/bin/bash
# 샌드박스 '사용자 폴더' — 프로그램 밖 git 저장소 (원격 origin 은 가짜 주소, push 안 함)
set -e
U=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/userproj
rm -rf $U && mkdir -p $U/orders-infra
cp /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/work/cap/scenarios/arch/orders-ecs/*.tf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/work/cap/scenarios/arch/orders-ecs/README.md $U/orders-infra/
cd $U/orders-infra
git init -q -b main
git -c user.email=t@example.com -c user.name=t add .
git -c user.email=t@example.com -c user.name=t commit -q -m "orders infra"
git remote add origin https://github.com/example/orders-infra.git
git remote set-url --push origin no-push-in-sandbox
git update-ref refs/remotes/origin/main HEAD
# 모듈 · data 소스가 있는 폴더 (지원 범위 밖 시험용)
mkdir -p $U/with-data && cd $U/with-data
cat > main.tf <<'TF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}
provider "aws" {
  region = "ap-northeast-2"
}
data "aws_vpc" "default" {
  default = true
}
resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
TF
mkdir -p $U/empty-folder
echo userproj ready
