variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "run_id" {
  type        = string
  description = "실행 식별자 (GitHub run id). 이름·태그에 붙어 남은 리소스 확인에 쓴다"
  default     = "local"
}

variable "instance_type" {
  type    = string
  default = "t3.micro" # D-18: t2.micro 는 프리 플랜 대상이 아님
}
