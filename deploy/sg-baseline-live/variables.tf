variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "instance_type" {
  type    = string
  default = "t3.micro" # D-18: t2.micro 는 프리 플랜 대상이 아님
}
