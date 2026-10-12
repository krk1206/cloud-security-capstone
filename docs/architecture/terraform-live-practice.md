# Terraform 즉석 작성 연습 세트 (교수님 테스트 대비)

목표: 빈 폴더에서 아무것도 안 보고 아래 Level 1을 20분 안에 작성하고 `terraform validate`를 통과시킨다.
방법: 이 파일을 닫는다 → 빈 폴더 `~/tf-practice`에서 작성 → `terraform init && terraform validate` → 이 파일과 비교 → 틀린 곳만 다시 → 3회 반복, 매회 걸린 시간을 기록한다.

## Level 1 (반드시 외울 것): VPC + 서브넷 2 + IGW + 라우트 + SG + EC2 1대

쓰는 순서와, 쓰면서 말할 설명:

1. provider: "리전과 provider 버전을 고정합니다"
2. aws_vpc: "CIDR 10.0.0.0/16, DNS 호스트네임 켭니다"
3. aws_subnet x2: "AZ a, c에 public 서브넷. 각 /24"
4. aws_internet_gateway: "VPC와 인터넷 사이 출입구"
5. aws_route_table + aws_route + aws_route_table_association: "0.0.0.0/0을 IGW로 보내는 라우트 테이블을 두 서브넷에 연결. 이 라우트가 있어서 public 서브넷입니다"
6. aws_security_group + 규칙: "SSH는 내 IP만, HTTP 80은 전체. 아웃바운드 443"
7. data aws_ami + aws_instance: "최신 AL2023, t3.micro, 공인 IP, IMDSv2, 루트 볼륨 암호화"
8. output: "public_ip"

    terraform {
      required_version = ">= 1.5"
      required_providers {
        aws = { source = "hashicorp/aws", version = "~> 5.0" }
      }
    }

    provider "aws" {
      region  = "ap-northeast-2"
      profile = "capstone"
    }

    variable "admin_cidr" { type = string }   # terraform.tfvars: admin_cidr = "x.x.x.x/32"

    resource "aws_vpc" "main" {
      cidr_block           = "10.0.0.0/16"
      enable_dns_hostnames = true
      tags = { Name = "practice-vpc" }
    }

    resource "aws_subnet" "public_a" {
      vpc_id            = aws_vpc.main.id
      cidr_block        = "10.0.0.0/24"
      availability_zone = "ap-northeast-2a"
      tags = { Name = "practice-public-a" }
    }

    resource "aws_subnet" "public_c" {
      vpc_id            = aws_vpc.main.id
      cidr_block        = "10.0.1.0/24"
      availability_zone = "ap-northeast-2c"
      tags = { Name = "practice-public-c" }
    }

    resource "aws_internet_gateway" "igw" {
      vpc_id = aws_vpc.main.id
    }

    resource "aws_route_table" "public" {
      vpc_id = aws_vpc.main.id
    }

    resource "aws_route" "internet" {
      route_table_id         = aws_route_table.public.id
      destination_cidr_block = "0.0.0.0/0"
      gateway_id             = aws_internet_gateway.igw.id
    }

    resource "aws_route_table_association" "a" {
      subnet_id      = aws_subnet.public_a.id
      route_table_id = aws_route_table.public.id
    }

    resource "aws_route_table_association" "c" {
      subnet_id      = aws_subnet.public_c.id
      route_table_id = aws_route_table.public.id
    }

    resource "aws_security_group" "web" {
      name        = "practice-web-sg"
      description = "SSH from admin, HTTP from anywhere"
      vpc_id      = aws_vpc.main.id
    }

    resource "aws_vpc_security_group_ingress_rule" "ssh" {
      security_group_id = aws_security_group.web.id
      cidr_ipv4         = var.admin_cidr
      from_port         = 22
      to_port           = 22
      ip_protocol       = "tcp"
    }

    resource "aws_vpc_security_group_ingress_rule" "http" {
      security_group_id = aws_security_group.web.id
      cidr_ipv4         = "0.0.0.0/0"
      from_port         = 80
      to_port           = 80
      ip_protocol       = "tcp"
    }

    resource "aws_vpc_security_group_egress_rule" "https_out" {
      security_group_id = aws_security_group.web.id
      cidr_ipv4         = "0.0.0.0/0"
      from_port         = 443
      to_port           = 443
      ip_protocol       = "tcp"
    }

    data "aws_ami" "al2023" {
      most_recent = true
      owners      = ["amazon"]
      filter {
        name   = "name"
        values = ["al2023-ami-2023*-x86_64"]
      }
    }

    resource "aws_instance" "web" {
      ami                         = data.aws_ami.al2023.id
      instance_type               = "t3.micro"
      subnet_id                   = aws_subnet.public_a.id
      vpc_security_group_ids      = [aws_security_group.web.id]
      associate_public_ip_address = true

      metadata_options {
        http_tokens = "required"
      }

      root_block_device {
        encrypted = true
      }

      tags = { Name = "practice-web" }
    }

    output "public_ip" {
      value = aws_instance.web.public_ip
    }

## Level 2 (Registry 보면서 쓸 수 있으면 됨)

- NAT Gateway: `aws_eip`(domain="vpc") → `aws_nat_gateway`(allocation_id, subnet_id=public) → private 라우트 테이블의 0.0.0.0/0을 `nat_gateway_id`로
- ALB: `aws_lb`(application, subnets=public 2개, security_groups) → `aws_lb_target_group`(port 80, vpc_id, health_check path "/") → `aws_lb_listener`(port 80, default_action forward)
- ASG: `aws_launch_template`(image_id, instance_type, vpc_security_group_ids, user_data=base64encode) → `aws_autoscaling_group`(min/max/desired, vpc_zone_identifier=private 서브넷, target_group_arns, launch_template{id, version="$Latest"})
- RDS: `aws_db_subnet_group`(subnet_ids 2개 AZ) → `aws_db_instance`(engine mysql, instance_class db.t3.micro, allocated_storage 20, username/password, db_subnet_group_name, vpc_security_group_ids, publicly_accessible=false, storage_encrypted=true, skip_final_snapshot=true)

## 자주 나는 에러와 뜻

| 메시지 | 원인 | 고치는 법 |
|---|---|---|
| `Reference to undeclared resource` | 리소스 이름 오타, 또는 `aws_subnet.public_a.id`처럼 타입.이름.속성 순서 틀림 | 선언한 이름과 맞춘다 |
| `Unsupported argument` | 그 리소스에 없는 속성 | Registry 문서의 Argument Reference 확인 |
| `Missing required argument` | 필수 속성 누락(예: aws_route_table_association의 route_table_id) | 추가 |
| `Cycle:` | SG 규칙을 인라인 블록으로 쓰면서 서로 참조 | 규칙을 `aws_vpc_security_group_*_rule` 리소스로 분리 |
| `InvalidKeyPair.NotFound` / `No valid credential sources` | 키 이름 또는 profile 문제 | `aws sts get-caller-identity --profile capstone`로 자격증명 먼저 확인 |

## 구두 설명 체크리스트 (한 문장씩)

- public/private 서브넷의 차이: 라우트 테이블에 0.0.0.0/0 → IGW 경로가 있으면 public, 없으면 private. 서브넷 자체에 public 속성은 없다.
- NAT Gateway가 public 서브넷에 있는 이유: 자기 자신이 IGW로 나가야 하기 때문. private 인스턴스 → NAT → IGW → 인터넷(응답만 돌아옴, 외부에서 시작하는 접속은 불가).
- Security Group은 상태 기반(stateful): 들어온 연결의 응답은 egress 규칙 없이도 나간다. 규칙은 허용만 있고 거부는 없다.
- SG 참조(referenced_security_group_id): "ALB SG를 가진 ENI에서 오는 트래픽"을 허용. IP가 바뀌어도 규칙이 유지된다.
- ALB(L7, HTTP 경로/헤더 기반) vs NLB(L4, TCP/UDP, 고정 IP, 매우 높은 처리량). 웹 앞은 ALB, 내부 서비스 간 TCP는 NLB가 일반적이다.
- 시작 템플릿은 인스턴스 설정의 묶음, ASG는 그 설정으로 인스턴스 개수를 유지하는 장치. ELB 헬스체크 실패 시 교체.
- RDS Multi-AZ(동기 복제 대기 인스턴스, 장애조치용, 읽기 불가)와 Read Replica(비동기 복제, 읽기 분산, 다른 리전 가능)는 다르다. 그림의 Master/Slave는 Primary + Read Replica.
- IAM 역할 + 인스턴스 프로파일: 인스턴스에 액세스 키를 두지 않고 임시 자격증명을 IMDS로 받는다. IMDSv2는 토큰 없이는 그 자격증명을 못 읽게 한다.
