variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "aws_profile" {
  description = "로컬 실행용 AWS CLI 프로필 이름. CI(OIDC)에서는 비워 둠(null)"
  type        = string
  default     = null
}

variable "project" {
  type    = string
  default = "capstone-iam-baseline"
}
