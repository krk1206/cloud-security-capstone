variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "aws_profile" {
  description = "로컬 AWS CLI 프로필 (팀 샌드박스 관리자). 예: capstone-tf"
  type        = string
  default     = null
}

variable "github_repo" {
  description = "OIDC 로 역할을 받을 수 있는 저장소 (owner/name)"
  type        = string
  default     = "krk1206/cloud-security-capstone"
}

variable "github_environment" {
  description = "워크플로 ③ 잡의 GitHub Environment 이름 (승인자가 걸려 있는 것)"
  type        = string
  default     = "sandbox"
}
