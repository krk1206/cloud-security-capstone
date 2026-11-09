# 입력 변수. 실제 apply 때 바꿀 값은 terraform.tfvars.example 을 terraform.tfvars 로 복사해 채운다 (tfvars 는 git 에 안 올라간다).

variable "aws_region" {
  description = "리전. 설계도 기준 도쿄."
  type        = string
  default     = "ap-northeast-1"
}

variable "project" {
  description = "리소스 이름 접두어이자 Project 태그 값."
  type        = string
  default     = "iacpatch-3tier"
}

variable "vpc_cidr" {
  description = "VPC 전체 사설 IP 대역."
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "가용 영역 두 곳 (설계도의 Availability Zone 2개)."
  type        = list(string)
  default     = ["ap-northeast-1a", "ap-northeast-1c"]
}

variable "public_subnet_cidrs" {
  description = "공개 서브넷 (Bastion, NAT, ALB). 가용 영역마다 하나."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "비공개 서브넷 (웹·API 서버, Redis, MySQL, NLB). 가용 영역마다 하나."
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "ami_id" {
  description = <<-EOT
    EC2 운영체제 이미지(AMI) ID. 리전마다 다르므로 변수로 받는다.
    기본값은 자격증명 없는 오프라인 plan(검증 파이프라인)용 자리표시자다 — 이 값으로 apply 하면 "AMI 없음" 오류로 멈춘다.
  EOT
  type        = string
  default     = "ami-0123456789abcdef0"

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id 는 ami-로 시작하는 16진수 ID 여야 한다."
  }
}

variable "instance_type" {
  description = "EC2 크기."
  type        = string
  default     = "t3.micro"
}

variable "domain_name" {
  description = "서비스 도메인 (Route53 공개 호스팅 영역). 시연용 자리표시자."
  type        = string
  default     = "iacpatch-demo.example"
}

variable "bucket_name" {
  description = "정적 자산·업로드 S3 버킷 이름 (전 세계 유일해야 한다)."
  type        = string
  default     = "iacpatch-3tier-assets-demo"
}

variable "db_name" {
  description = "MySQL 데이터베이스 이름."
  type        = string
  default     = "appdb"
}
