# variables.tf - 바꿀 수 있는 값은 전부 여기. 실제 값은 terraform.tfvars(커밋 금지)에서 온다.
variable "region" {
  type    = string
  default = "ap-northeast-2" # Seoul. 교수님 그림의 Tokyo(ap-northeast-1) 대신 샌드박스 리전 사용
}

variable "aws_profile" {
  type    = string
  default = null
}

variable "project" {
  type    = string
  default = "capstone-three-tier" # 리소스 이름 접두어
}

variable "vpc_cidr" {
  type    = string
  default = "10.10.0.0/16"
}

variable "azs" {
  type        = list(string)
  description = "가용 영역 2개. 인덱스 0, 1이 각각 AZ-a, AZ-c"
  default     = ["ap-northeast-2a", "ap-northeast-2c"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.10.0.0/24", "10.10.1.0/24"] # Bastion, NAT Gateway, ALB
}

variable "app_subnet_cidrs" {
  type    = list(string)
  default = ["10.10.10.0/24", "10.10.11.0/24"] # WEB ASG (API ASG는 다음 단계)
}

variable "db_subnet_cidrs" {
  type    = list(string)
  default = ["10.10.20.0/24", "10.10.21.0/24"] # RDS MySQL (서브넷 그룹은 AZ 2개 필수)
}

variable "admin_cidr" {
  type        = string
  description = "Bastion SSH를 허용할 출발지. 내 공인 IP/32 하나만"
}

variable "ssh_public_key" {
  type        = string
  description = "Bastion에 등록할 SSH 공개키 문자열 (ssh-ed25519 AAAA...)"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "web_desired" {
  type    = number
  default = 1 # 비용 때문에 1. ASG min 1 / max 2
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "db_username" {
  type    = string
  default = "admin"
}

variable "db_password" {
  type      = string
  sensitive = true # plan/apply 출력에서 가려짐. terraform.tfvars에서만 공급
}
