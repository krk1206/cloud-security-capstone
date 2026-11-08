# 주문 API (컨테이너) 예제 — 3계층 예제와 다른 구조: 인터넷 → ALB → ECS Fargate(주문 API) → PostgreSQL, 운영 서버(EC2)로 DB 점검.
# AWS 를 조회하는 data 소스는 쓰지 않는다 (자격증명 없이 plan 이 되게).

variable "aws_region" {
  description = "리소스를 만들 리전. 서울."
  type        = string
  default     = "ap-northeast-2"
}

variable "project" {
  description = "리소스 이름 접두어 · Project 태그."
  type        = string
  default     = "orders"
}

variable "vpc_cidr" {
  description = "VPC 전체 사설 IP 대역."
  type        = string
  default     = "10.20.0.0/16"
}

variable "azs" {
  description = "서브넷을 둘 가용 영역 두 곳."
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2c"]
}

variable "admin_cidrs" {
  description = "운영 서버에 SSH 로 들어올 수 있는 관리자 대역 (사무실 · VPN)."
  type        = list(string)
  default     = ["203.0.113.0/24"]
}

variable "ops_ami_id" {
  description = "운영 서버 AMI (예시 값 — 실제 배포 때 바꾼다)."
  type        = string
  default     = "ami-0abcdef1234567890"
}

variable "api_image" {
  description = "주문 API 컨테이너 이미지."
  type        = string
  default     = "public.ecr.aws/nginx/nginx:1.27"
}
