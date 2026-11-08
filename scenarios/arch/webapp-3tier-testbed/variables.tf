variable "aws_region" {
  description = "시험 환경 리전 (팀 샌드박스는 서울만 허용)"
  type        = string
  default     = "ap-northeast-2"
}

variable "project" {
  description = "이름 접두어. 보안 그룹 이름(security_groups.tf)에도 쓰인다."
  type        = string
  default     = "iacpatch-tb"
}

variable "vpc_cidr" {
  description = "설계도(arch-3tier-flows.json)의 vpc_cidr 와 같아야 한다 — V7 의 'VPC 안 모든 서버' 계산 기준"
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "가용 영역 2곳 (ALB 는 2곳 이상 필요)"
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2c"]
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "admin_vantage_cidr" {
  description = <<-EOT
    관리자 측정 지점을 둘 대역. 설계도의 관리자 허용 목록(203.0.113.0/24, 198.51.100.0/24) 중 하나여야 한다.
    문서용 예시 대역이라 인터넷에는 이 주소를 가진 컴퓨터가 없다. 그래서 VPC 에 보조 CIDR 로 붙이고 그 안에 측정 서버를 둔다
    (AWS 는 RFC 1918 밖의 대역도 VPC CIDR 로 허용 — VPC 사용 설명서 'VPC CIDR blocks').
  EOT
  type        = string
  default     = "198.51.100.0/24"
}
