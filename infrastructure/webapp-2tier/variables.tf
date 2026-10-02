# 입력 변수. 값은 (1) 여기 default, (2) terraform.tfvars 파일, (3) -var 옵션 순으로 덮어쓰인다.
# 실제 apply 때 바꿀 것은 terraform.tfvars.example 을 terraform.tfvars 로 복사해 채운다 (tfvars 는 git 에 안 올라간다).

variable "aws_region" {
  description = "리소스를 만들 리전. 서울."
  type        = string
  default     = "ap-northeast-2"
}

variable "project" {
  description = "리소스 이름 앞에 붙는 접두어이자 Project 태그 값."
  type        = string
  default     = "iacpatch-webapp"
}

variable "vpc_cidr" {
  description = "VPC 전체 사설 IP 대역."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "인터넷에서 들어올 수 있는 서브넷(웹 서버)."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "인터넷에서 직접 못 들어오는 서브넷(앱 서버)."
  type        = string
  default     = "10.0.2.0/24"
}

variable "availability_zone" {
  description = "두 서브넷을 둘 가용 영역."
  type        = string
  default     = "ap-northeast-2a"
}

variable "ami_id" {
  description = <<-EOT
    EC2 에 올릴 운영체제 이미지(AMI) ID. 리전마다 다르고 수시로 갱신되므로 코드에 박지 않고 변수로 받는다.
    실제 apply 전에 콘솔(EC2 → 인스턴스 시작 → Amazon Linux 2023 의 AMI ID)에서 복사해 terraform.tfvars 에 적는다.
    기본값은 자격증명 없는 오프라인 plan(검증 파이프라인)용 자리표시자다 — 이 값으로 apply 하면 "AMI 없음" 오류로 멈춘다.
  EOT
  type        = string
  default     = "ami-0123456789abcdef0"

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id 는 ami-로 시작하는 16진수 ID 여야 한다 (예: ami-0abc123def4567890)."
  }
}

variable "instance_type" {
  description = <<-EOT
    EC2 크기. 기본 t2.micro = 서울 리전 프리 티어 대상(12개월 월 750시간 무료). 2025-07 이후 새 계정(크레딧 플랜)은 어느 쪽이든 크레딧 안.
    시연 1시간 × 2대 = 2시간 — 프리 티어 안이면 0원, 밖이어도 수십 원.
  EOT
  type        = string
  default     = "t2.micro"
}

variable "bucket_name" {
  description = <<-EOT
    정적 자산 S3 버킷 이름. S3 버킷 이름은 전 세계에서 유일해야 하므로 apply 때 겹치면 바꾼다.
    바꾸면 experiments/candidate-sets/arch-webapp-iam/intents/ 의 IAM intent ARN 도 같이 바꿔야 한다 (평가용 고정값).
  EOT
  type        = string
  default     = "iacpatch-webapp-assets-demo"
}
